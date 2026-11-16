/* Relé TCP: o motor "termina" o TCP do app. Para o app, o motor faz o papel do servidor
 * (handshake, números de sequência, janela, FIN); para o servidor real, quem fala TCP é o
 * kernel, pelo socket do motor. No meio passam só os bytes. Aulas 04 (seção 7) e 05 (seção 7).
 *
 * Nomes dos números de sequência (como na RFC 9293):
 *   rcv_prox  próximo byte que esperamos do app
 *   snd_una   byte mais antigo que mandamos ao app e ele ainda não confirmou
 *   snd_prox  próximo byte que vamos mandar ao app
 * Comparações sempre pela diferença com sinal (a sequência dá a volta em 2^32).
 *
 * Sem opção Window Scale no SYN-ACK: a escala fica desligada nos dois sentidos e as janelas
 * cabem em 16 bits (até 65535 bytes).
 */
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "motor_interno.h"

enum {
    CONECTANDO,
    ABERTO,
    MAX_JANELA = 65535,         /* buffers dos dois sentidos */
    MSS_PADRAO = 536,           /* RFC 9293: sem opção MSS */
    RTO_US = 1000000,           /* retransmissão por tempo para o app */
    SNI_MAX = 16384 + 9,        /* um registro TLS inteiro; acima disso, desiste */
};

typedef struct {
    sn_estado base;
    int etapa;
    uint32_t isn;               /* nosso número inicial */
    uint32_t rcv_prox, snd_una, snd_prox;
    uint32_t janela_app;        /* quanto o app aceita além de snd_una */
    uint16_t mss;               /* tamanho dos segmentos para o app */
    uint8_t *ps;                /* bytes do app ainda não enviados ao servidor */
    size_t n_ps, cap_ps;
    uint8_t *nc;                /* bytes enviados ao app e não confirmados (começam em snd_una) */
    size_t n_nc, cap_nc;
    int fin_app, shut_wr, eof_servidor, fin_enviado;
    int syn_confirmado;         /* o app já confirmou o nosso SYN */
    int dup_acks;
    int em_recuperacao;         /* reenviando buracos, um segmento por ACK (NewReno, RFC 6582) */
    uint32_t recuperacao_ate;   /* snd_prox quando a recuperação começou */
    uint64_t ultimo_envio;      /* monotônico; base da retransmissão por tempo */
    uint8_t *ci;                /* começo do fluxo do app, para achar o SNI */
    size_t n_ci, cap_ci;
    int sni_fim;
} estado_tcp;

static int32_t dif(uint32_t a, uint32_t b) { return (int32_t)(a - b); }

static void liberar_buffers(sn_estado *base) {
    estado_tcp *e = (estado_tcp *)base;
    free(e->ps);
    free(e->nc);
    free(e->ci);
}

static void consome(uint8_t *buf, size_t *n, size_t k) {
    if (k == 0)
        return; /* buf pode ainda ser NULL */
    memmove(buf, buf + k, *n - k);
    *n -= k;
}

/* ---------------------------------------------------------------- envio ao app */

static uint16_t janela_nossa(const estado_tcp *e) { return (uint16_t)(MAX_JANELA - e->n_ps); }

static int para_app(sn_motor *m, sn_fluxo *f, estado_tcp *e, uint32_t seq, uint8_t flags,
                    uint16_t mss, const uint8_t *d, size_t n, sn_tempo agora) {
    sn_tupla v = sn_tupla_inversa(&f->tupla);
    size_t tam = sn_montar_tcp(m->tx, sizeof m->tx, &v, seq, e->rcv_prox, flags, janela_nossa(e), mss, d, n);
    if (tam == 0 || sn_escrever_tun(m, m->tx, tam, agora) != 0)
        return -1;
    f->pacotes++;
    e->base.alterado = 1;
    return 0;
}

/* RST para um segmento que não pertence a nenhuma conexão viva (RFC 9293 §3.10.7.1). */
static void rst_resposta(sn_motor *m, const sn_tupla *k, const sn_tcp *t, size_t len, sn_tempo agora) {
    sn_tupla v = sn_tupla_inversa(k);
    size_t tam;
    if (t->flags & SN_TCP_ACK) {
        tam = sn_montar_tcp(m->tx, sizeof m->tx, &v, t->ack, 0, SN_TCP_RST, 0, 0, NULL, 0);
    } else {
        uint32_t ack = t->seq + (uint32_t)len + ((t->flags & SN_TCP_SYN) ? 1u : 0u) +
                       ((t->flags & SN_TCP_FIN) ? 1u : 0u);
        tam = sn_montar_tcp(m->tx, sizeof m->tx, &v, 0, ack, SN_TCP_RST | SN_TCP_ACK, 0, 0, NULL, 0);
    }
    if (tam)
        sn_escrever_tun(m, m->tx, tam, agora);
}

/* abortar = 1 fecha com RST para o servidor (SO_LINGER zerado), em vez de FIN. */
static void fechar(sn_fluxo *f, estado_tcp *e, uint8_t motivo, int abortar, sn_tempo agora) {
    if (e->base.fd >= 0) {
        if (abortar) {
            struct linger l = {.l_onoff = 1, .l_linger = 0};
            setsockopt(e->base.fd, SOL_SOCKET, SO_LINGER, &l, sizeof l);
        }
        close(e->base.fd);
    }
    e->base.fd = -1;
    e->base.eventos = 0;
    f->fechado = 1;
    f->fechado_us = agora.mono;
    f->fim_us = agora.parede;
    f->motivo_fim = motivo;
}

static void rst_e_fecha(sn_motor *m, sn_fluxo *f, estado_tcp *e, uint8_t motivo, sn_tempo agora) {
    para_app(m, f, e, e->snd_prox, SN_TCP_RST | SN_TCP_ACK, 0, NULL, 0, agora);
    fechar(f, e, motivo, 1, agora);
}

/* Quanto ainda podemos mandar ao app: janela dele menos o que está em voo, limitado pelo buffer. */
static size_t pode_mandar(const estado_tcp *e) {
    int32_t livre = dif(e->snd_una + e->janela_app, e->snd_prox);
    size_t janela = livre > 0 ? (size_t)livre : 0;
    size_t buffer = MAX_JANELA - e->n_nc;
    return janela < buffer ? janela : buffer;
}

static void atualiza_eventos(estado_tcp *e) {
    short ev = 0;
    if (e->base.fd >= 0) {
        if (e->etapa == CONECTANDO)
            ev = POLLOUT;
        else {
            if (e->n_ps > 0)
                ev |= POLLOUT;
            if (!e->eof_servidor && pode_mandar(e) > 0)
                ev |= POLLIN;
        }
    }
    e->base.eventos = ev;
}

/* Encerrou dos dois lados e o app confirmou o nosso FIN? */
static void talvez_encerrado(sn_fluxo *f, estado_tcp *e, sn_tempo agora) {
    if (e->fin_app && e->shut_wr && e->fin_enviado && e->snd_una == e->snd_prox)
        fechar(f, e, SN_FIM_FECHADO, 0, agora);
}

/* Reenvia o primeiro pendente a partir de snd_una: o SYN-ACK, um segmento de dados, ou o
 * FIN. Só um: reenviar a janela inteira a cada perda multiplicava o tráfego (cada cópia
 * repetida gera outro ACK duplicado no app). Os buracos seguintes saem pelos ACKs parciais. */
static void retransmite(sn_motor *m, sn_fluxo *f, estado_tcp *e, sn_tempo agora) {
    if (!e->syn_confirmado) {
        para_app(m, f, e, e->isn, SN_TCP_SYN | SN_TCP_ACK, e->mss, NULL, 0, agora);
    } else if (e->n_nc > 0) {
        size_t k = e->n_nc < e->mss ? e->n_nc : e->mss;
        para_app(m, f, e, e->snd_una, SN_TCP_ACK | SN_TCP_PSH, 0, e->nc, k, agora);
    } else if (e->fin_enviado) {
        para_app(m, f, e, e->snd_prox - 1, SN_TCP_FIN | SN_TCP_ACK, 0, NULL, 0, agora);
    }
    e->ultimo_envio = agora.mono;
}

static void inicia_recuperacao(sn_motor *m, sn_fluxo *f, estado_tcp *e, sn_tempo agora) {
    e->em_recuperacao = 1;
    e->recuperacao_ate = e->snd_prox;
    retransmite(m, f, e, agora);
}

/* ---------------------------------------------------------------- servidor -> app */

static void manda_fin(sn_motor *m, sn_fluxo *f, estado_tcp *e, sn_tempo agora) {
    if (e->fin_enviado)
        return;
    para_app(m, f, e, e->snd_prox, SN_TCP_FIN | SN_TCP_ACK, 0, NULL, 0, agora);
    e->snd_prox++;
    e->fin_enviado = 1;
    e->ultimo_envio = agora.mono;
}

static void le_servidor(sn_motor *m, sn_fluxo *f, estado_tcp *e, sn_tempo agora) {
    size_t cabe = pode_mandar(e);
    if (cabe == 0)
        return;
    if (cabe > sizeof m->rx)
        cabe = sizeof m->rx;
    ssize_t n = recv(e->base.fd, m->rx, cabe, 0);
    if (n == 0) {
        e->eof_servidor = 1;
        manda_fin(m, f, e, agora);
        return;
    }
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            rst_e_fecha(m, f, e, SN_FIM_RESET, agora);
        return;
    }
    if (sn_anexa(&e->nc, &e->n_nc, &e->cap_nc, m->rx, (size_t)n, MAX_JANELA) != 0) {
        rst_e_fecha(m, f, e, SN_FIM_ERRO, agora); /* sem memória: não dá para seguir sem perder bytes */
        return;
    }
    for (size_t i = 0; i < (size_t)n;) {
        size_t k = (size_t)n - i < e->mss ? (size_t)n - i : e->mss;
        uint8_t flags = (uint8_t)(SN_TCP_ACK | (i + k == (size_t)n ? SN_TCP_PSH : 0));
        para_app(m, f, e, e->snd_prox, flags, 0, m->rx + i, k, agora);
        e->snd_prox += (uint32_t)k;
        i += k;
    }
    f->bytes_rec += (uint64_t)n;
    f->ultimo_us = agora.mono;
    e->ultimo_envio = agora.mono;
}

/* ---------------------------------------------------------------- app -> servidor */

static void esvazia_para_servidor(sn_motor *m, sn_fluxo *f, estado_tcp *e, sn_tempo agora) {
    uint16_t antes = janela_nossa(e);
    while (e->n_ps > 0) {
        ssize_t n = send(e->base.fd, e->ps, e->n_ps, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                rst_e_fecha(m, f, e, SN_FIM_RESET, agora);
            break;
        }
        consome(e->ps, &e->n_ps, (size_t)n);
        f->bytes_env += (uint64_t)n; /* conta o que de fato foi entregue ao servidor */
    }
    if (f->fechado)
        return;
    if (e->n_ps == 0 && e->fin_app && !e->shut_wr) {
        shutdown(e->base.fd, SHUT_WR); /* repassa o FIN do app ao servidor */
        e->shut_wr = 1;
    }
    /* Janela saiu de quase fechada: avisa o app para ele voltar a mandar. */
    if (antes < e->mss && janela_nossa(e) >= e->mss)
        para_app(m, f, e, e->snd_prox, SN_TCP_ACK, 0, NULL, 0, agora);
}

static void procura_sni(sn_motor *m, sn_fluxo *f, estado_tcp *e, const uint8_t *d, size_t n) {
    if (e->sni_fim || n == 0)
        return;
    size_t k = e->n_ci + n > SNI_MAX ? SNI_MAX - e->n_ci : n;
    if (sn_anexa(&e->ci, &e->n_ci, &e->cap_ci, d, k, SNI_MAX) != 0) {
        e->sni_fim = 1;
        return;
    }
    char nome[SN_NOME_MAX + 1];
    int ech = 0;
    int r = sn_tls_sni(e->ci, e->n_ci, nome, sizeof nome, &ech);
    if (r == SN_OK)
        sn_ev_sni(m, f, nome, ech);
    if (r != SN_ERR_CURTO || e->n_ci >= SNI_MAX) {
        e->sni_fim = 1;
        free(e->ci);
        e->ci = NULL;
        e->n_ci = e->cap_ci = 0;
    }
}

static void processa_ack(sn_motor *m, sn_fluxo *f, estado_tcp *e, const sn_tcp *t, size_t len, sn_tempo agora) {
    int32_t avanco = dif(t->ack, e->snd_una);
    e->janela_app = t->janela;
    if (avanco > 0 && dif(t->ack, e->snd_prox) <= 0) {
        size_t dados = (size_t)avanco;
        if (!e->syn_confirmado) {
            dados--; /* o primeiro byte confirmado é o nosso SYN */
            e->syn_confirmado = 1;
        }
        if (dados > e->n_nc)
            dados = e->n_nc; /* o resto é o nosso FIN */
        consome(e->nc, &e->n_nc, dados);
        e->snd_una = t->ack;
        e->dup_acks = 0;
        e->ultimo_envio = agora.mono;
        if (e->em_recuperacao) {
            if (dif(t->ack, e->recuperacao_ate) >= 0)
                e->em_recuperacao = 0;      /* todos os buracos fechados */
            else
                retransmite(m, f, e, agora); /* ACK parcial: o próximo buraco */
        }
    } else if (avanco == 0 && len == 0 && e->n_nc > 0) {
        /* ACK duplicado: o app recebeu algo fora de ordem e pede de novo o mesmo ponto */
        if (++e->dup_acks == 3 && !e->em_recuperacao)
            inicia_recuperacao(m, f, e, agora);
    }
}

/* ---------------------------------------------------------------- entrada do app */

static void novo_fluxo(sn_motor *m, const sn_ip *ip, const sn_tupla *k, const sn_tcp *t, sn_tempo agora) {
    estado_tcp *e = calloc(1, sizeof *e);
    if (!e)
        return;
    sn_fluxo *f = sn_novo_fluxo(m, k, agora);
    if (!f) {
        free(e);
        return;
    }
    f->estado = e;
    e->base.liberar_extra = liberar_buffers;
    e->rcv_prox = t->seq + 1;
    e->janela_app = t->janela;
    uint16_t nosso = ip->versao == 4 ? 1460 : 1440; /* MTU 1500 do tun menos cabeçalhos */
    uint16_t dele = t->mss ? t->mss : MSS_PADRAO;
    e->mss = dele < nosso ? dele : nosso;
    e->isn = (uint32_t)(agora.mono * 2654435761u) ^ (f->id * 40503u);
    e->snd_una = e->snd_prox = e->isn;
    f->pacotes = 1;
    f->ultimo_us = agora.mono;
    sn_ev_fluxo_novo(m, f);

    /* DNS por TCP (resposta UDP truncada) no DNS virtual vai ao DNS real, como no UDP. */
    sn_endereco destino;
    uint16_t porta;
    e->base.fd = sn_destino_real(m, k, &destino, &porta) == 0 ? sn_socket_para(&destino, porta, SOCK_STREAM) : -1;
    if (e->base.fd < 0) {
        para_app(m, f, e, 0, SN_TCP_RST | SN_TCP_ACK, 0, NULL, 0, agora);
        fechar(f, e, SN_FIM_ERRO, 0, agora);
        return;
    }
    e->etapa = CONECTANDO;
    atualiza_eventos(e);
}

void sn_tcp_do_app(sn_motor *m, const sn_ip *ip, const uint8_t *pkt, sn_tempo agora) {
    const uint8_t *l4 = pkt + ip->tam_cabecalho;
    size_t n4 = ip->tam_total - ip->tam_cabecalho;
    sn_tcp t;
    if (sn_tcp_ler(l4, n4, &t) != SN_OK)
        return;
    const uint8_t *d = l4 + t.tam_cabecalho;
    size_t len = n4 - t.tam_cabecalho;

    sn_tupla k = sn_tupla_de(ip, SN_PROTO_TCP, t.porta_origem, t.porta_destino);
    sn_fluxo *f = sn_fluxos_achar(m->fluxos, &k);

    if (!f || f->fechado) {
        if (t.flags & SN_TCP_RST)
            return;
        if (!f && (t.flags & SN_TCP_SYN) && !(t.flags & SN_TCP_ACK))
            novo_fluxo(m, ip, &k, &t, agora);
        else
            rst_resposta(m, &k, &t, len, agora);
        return;
    }

    estado_tcp *e = f->estado;
    f->pacotes++;
    f->ultimo_us = agora.mono;
    e->base.alterado = 1;

    if (t.flags & SN_TCP_RST) {
        fechar(f, e, SN_FIM_RESET, 1, agora); /* repassa como RST, não como FIN */
        return;
    }
    if ((t.flags & SN_TCP_SYN) || e->etapa == CONECTANDO)
        return; /* SYN repetido, ou o app se adiantando antes do SYN-ACK: ignorados */

    if (t.flags & SN_TCP_ACK)
        processa_ack(m, f, e, &t, len, agora);

    int32_t desloc = dif(t.seq, e->rcv_prox);
    if (len == 0 && !(t.flags & SN_TCP_FIN) && desloc != 0) {
        /* Sonda de keepalive ou de janela zero (seq fora do esperado, sem dados): a RFC 9293
         * §3.10.7.4 manda responder com ACK, senão o app derruba a conexão sadia. */
        para_app(m, f, e, e->snd_prox, SN_TCP_ACK, 0, NULL, 0, agora);
    }
    if (len > 0 || (t.flags & SN_TCP_FIN)) {
        if (desloc <= 0 && desloc != INT32_MIN && !e->fin_app) {
            size_t velho = (size_t)(-desloc);
            size_t novo = len > velho ? len - velho : 0;
            size_t aceita = novo < janela_nossa(e) ? novo : janela_nossa(e);
            if (aceita && sn_anexa(&e->ps, &e->n_ps, &e->cap_ps, d + velho, aceita, MAX_JANELA) == 0) {
                procura_sni(m, f, e, d + velho, aceita);
                e->rcv_prox += (uint32_t)aceita;
            }
            if ((t.flags & SN_TCP_FIN) && dif(t.seq + (uint32_t)len, e->rcv_prox) == 0) {
                e->rcv_prox++;
                e->fin_app = 1;
            }
            esvazia_para_servidor(m, f, e, agora);
            if (f->fechado)
                return;
        }
        /* Fora de ordem (desloc > 0) é descartado: o ACK abaixo repete o ponto que esperamos. */
        para_app(m, f, e, e->snd_prox, SN_TCP_ACK, 0, NULL, 0, agora);
    }
    talvez_encerrado(f, e, agora);
    atualiza_eventos(e);
}

/* ---------------------------------------------------------------- socket pronto */

void sn_tcp_socket(sn_motor *m, sn_fluxo *f, short revents, sn_tempo agora) {
    estado_tcp *e = f->estado;
    if (e->etapa == CONECTANDO) {
        int err = 0;
        socklen_t tam = sizeof err;
        getsockopt(e->base.fd, SOL_SOCKET, SO_ERROR, &err, &tam);
        if (err || (revents & (POLLERR | POLLHUP))) {
            para_app(m, f, e, 0, SN_TCP_RST | SN_TCP_ACK, 0, NULL, 0, agora);
            fechar(f, e, SN_FIM_ERRO, 0, agora);
            return;
        }
        e->etapa = ABERTO;
        para_app(m, f, e, e->isn, SN_TCP_SYN | SN_TCP_ACK, e->mss, NULL, 0, agora);
        e->snd_prox = e->isn + 1;
        e->ultimo_envio = agora.mono;
        atualiza_eventos(e);
        return;
    }
    if (revents & POLLOUT)
        esvazia_para_servidor(m, f, e, agora);
    if (!f->fechado && (revents & (POLLIN | POLLHUP | POLLERR)))
        le_servidor(m, f, e, agora);
    if (!f->fechado) {
        talvez_encerrado(f, e, agora);
        atualiza_eventos(e);
    }
}

void sn_tcp_tique(sn_motor *m, sn_fluxo *f, sn_tempo agora) {
    estado_tcp *e = f->estado;
    if (!e || e->etapa != ABERTO)
        return;
    if (e->snd_una != e->snd_prox) {
        if (agora.mono - e->ultimo_envio >= RTO_US)
            inicia_recuperacao(m, f, e, agora); /* um segmento; os buracos seguintes por ACK parcial */
    } else if (e->janela_app == 0 && !e->eof_servidor && e->syn_confirmado) {
        /* Janela do app fechada e nada em voo: sonda (seq antigo, sem dados) para o app
         * responder com a janela atual, caso o aviso de reabertura tenha se perdido. */
        para_app(m, f, e, e->snd_prox - 1, SN_TCP_ACK, 0, NULL, 0, agora);
    }
    atualiza_eventos(e);
}
