/* O laço do motor: lê pacotes dos apps no tun, entrega a cada relé, acorda com as
 * respostas dos sockets reais e, uma vez por segundo, publica bytes e expira fluxos.
 * Contrato em include/sentinela.h; aula 05 (sockets, poll, TUN).
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "motor_interno.h"

enum {
    TIQUE_US = 1000000,       /* publica bytes e expira a cada 1 s */
    POLL_MS = 250,            /* o laço acorda pelo menos 4 vezes por segundo */
    MAX_LIDOS_POR_VOLTA = 256 /* não deixa o tun monopolizar o laço */
};

static uint64_t relogio_sistema(clockid_t qual) {
    struct timespec ts;
    clock_gettime(qual, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

sn_tempo sn_agora(const sn_motor *m) {
    sn_tempo t;
    t.parede = m->c.relogio_us ? m->c.relogio_us(m->c.relogio_ctx) : relogio_sistema(CLOCK_REALTIME);
    t.mono = m->c.relogio_mono_us ? m->c.relogio_mono_us(m->c.relogio_ctx)
                                  : relogio_sistema(CLOCK_MONOTONIC);
    return t;
}

sn_fluxo *sn_novo_fluxo(sn_motor *m, const sn_tupla *k, sn_tempo agora) {
    sn_fluxo *f = sn_fluxos_inserir(m->fluxos, k, agora.mono); /* prazos no monotônico */
    if (f)
        f->inicio_us = agora.parede;                            /* evento na hora de parede */
    return f;
}

static int limita(int n, int max) { return n < 0 ? 0 : n > max ? max : n; }

static void nao_bloqueante(int fd) {
    int fl = fcntl(fd, F_GETFL);
    if (fl >= 0)
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

sn_motor *sn_motor_criar(const sn_config *c) {
    sn_motor *m = calloc(1, sizeof *m);
    if (!m)
        return NULL;
    m->c = *c;
    m->c.caminho_pcap = NULL; /* não guardamos ponteiro de quem chamou */
    m->c.n_dns_virtual = limita(m->c.n_dns_virtual, 2);
    m->c.n_dns_real = limita(m->c.n_dns_real, SN_MAX_DNS_REAIS);
    m->fd_tun = -1;
    pthread_mutex_init(&m->mu_dns, NULL);
    m->fd_parar = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    m->fluxos = sn_fluxos_criar();
    if (m->fd_parar < 0 || !m->fluxos || sn_fila_iniciar(&m->fila) != 0)
        goto falha;
    if (c->caminho_pcap && !(m->pcap = sn_pcap_abrir(c->caminho_pcap)))
        goto falha;
    return m;
falha:
    if (m->fd_parar >= 0)
        close(m->fd_parar);
    sn_fluxos_destruir(m->fluxos, NULL, NULL);
    pthread_mutex_destroy(&m->mu_dns);
    free(m);
    return NULL;
}

void sn_motor_parar(sn_motor *m) {
    uint64_t um = 1;
    ssize_t r = write(m->fd_parar, &um, sizeof um);
    (void)r; /* se o contador já estiver cheio, o pedido anterior basta */
}

size_t sn_motor_eventos(sn_motor *m, uint8_t *buf, size_t cap) {
    return sn_fila_tirar(&m->fila, buf, cap);
}

int sn_escrever_tun(sn_motor *m, const uint8_t *p, size_t n, sn_tempo agora) {
    /* Tun cheio ou fora: o pacote se perde (o TCP do app retransmite). Só o que entrou no
     * tun vai para o pcap, que é evidência do que de fato passou. */
    if (write(m->fd_tun, p, n) != (ssize_t)n)
        return -1;
    if (m->pcap)
        sn_pcap_gravar(m->pcap, agora.parede, p, n);
    return 0;
}

int sn_socket_para(const sn_endereco *e, uint16_t porta, int tipo) {
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    socklen_t tam;
    int familia;
    if (e->versao == 4) {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_port = htons(porta);
        memcpy(&a->sin_addr, e->ip, 4);
        tam = sizeof *a;
        familia = AF_INET;
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(porta);
        memcpy(&a->sin6_addr, e->ip, 16);
        tam = sizeof *a;
        familia = AF_INET6;
    }
    int fd = socket(familia, tipo | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (connect(fd, (struct sockaddr *)&ss, tam) != 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    return fd;
}

void sn_relay_liberar(sn_fluxo *f) {
    sn_estado *e = f->estado;
    if (!e)
        return;
    if (e->fd >= 0)
        close(e->fd);
    if (e->liberar_extra)
        e->liberar_extra(e);
    free(e);
    f->estado = NULL;
}

/* ---------------------------------------------------------------- tique: bytes e expiração */

static void publica_bytes(void *ctx, sn_fluxo *f) {
    sn_estado *e = f->estado;
    if (e && e->alterado) {
        sn_ev_bytes(ctx, f);
        e->alterado = 0;
    }
}

static void saida(void *ctx, sn_fluxo *f, uint8_t motivo) {
    sn_motor *m = ctx;
    publica_bytes(m, f);
    uint8_t mot = f->fechado ? f->motivo_fim : motivo;
    sn_ev_fim(m, f, f->fechado ? f->fim_us : sn_agora(m).parede, mot);
    sn_relay_liberar(f);
}

typedef struct {
    sn_motor *m;
    sn_tempo agora;
} ctx_tique;

static void tique_tcp(void *ctx, sn_fluxo *f) {
    ctx_tique *c = ctx;
    if (f->tupla.protocolo == SN_PROTO_TCP && !f->fechado)
        sn_tcp_tique(c->m, f, c->agora);
}

static void tique(sn_motor *m, sn_tempo agora) {
    if (agora.mono - m->ultimo_tique < TIQUE_US)
        return;
    m->ultimo_tique = agora.mono;
    ctx_tique c = {m, agora};
    sn_fluxos_cada(m->fluxos, tique_tcp, &c);
    sn_fluxos_cada(m->fluxos, publica_bytes, m);
    sn_fluxos_expirar(m->fluxos, agora.mono, saida, m);
}

/* ---------------------------------------------------------------- pacotes dos apps */

static void pacote_do_app(sn_motor *m, const uint8_t *p, size_t n, sn_tempo agora) {
    if (m->pcap)
        sn_pcap_gravar(m->pcap, agora.parede, p, n);
    sn_ip ip;
    if (sn_ip_ler(p, n, &ip) != SN_OK)
        return; /* fragmento ou lixo: descartado (fica só no pcap) */
    if (ip.protocolo == SN_PROTO_UDP)
        sn_udp_do_app(m, &ip, p, agora);
    else if (ip.protocolo == SN_PROTO_TCP)
        sn_tcp_do_app(m, &ip, p, agora);
    /* ICMP e o resto: fora da v1 */
}

/* ---------------------------------------------------------------- o laço */

typedef struct {
    struct pollfd *pf;
    sn_fluxo **fl;
    size_t n, cap;
} conjunto;

static int conjunto_por(conjunto *c, int fd, short ev, sn_fluxo *f) {
    if (c->n == c->cap) {
        size_t novo = c->cap ? c->cap * 2 : 64;
        struct pollfd *pf = realloc(c->pf, novo * sizeof *pf);
        if (!pf)
            return -1;
        c->pf = pf;
        sn_fluxo **fl = realloc(c->fl, novo * sizeof *fl);
        if (!fl)
            return -1;
        c->fl = fl;
        c->cap = novo;
    }
    c->pf[c->n] = (struct pollfd){.fd = fd, .events = ev};
    c->fl[c->n] = f;
    c->n++;
    return 0;
}

static void junta_fluxo(void *ctx, sn_fluxo *f) {
    sn_estado *e = f->estado;
    if (e && e->fd >= 0 && e->eventos)
        conjunto_por(ctx, e->fd, e->eventos, f);
}

int sn_motor_rodar(sn_motor *m, int fd_tun) {
    m->fd_tun = fd_tun;
    nao_bloqueante(fd_tun);
    m->ultimo_tique = sn_agora(m).mono;
    conjunto c = {0};
    int ret = 0;
    for (;;) {
        tique(m, sn_agora(m)); /* expira antes de montar o conjunto: ponteiros seguros */
        c.n = 0;
        if (conjunto_por(&c, m->fd_parar, POLLIN, NULL) != 0 ||
            conjunto_por(&c, fd_tun, POLLIN, NULL) != 0) {
            ret = -1; /* sem memória nem para o básico */
            break;
        }
        sn_fluxos_cada(m->fluxos, junta_fluxo, &c);

        int r = poll(c.pf, (nfds_t)c.n, POLL_MS);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            ret = -1;
            break;
        }
        if (c.pf[0].revents & POLLIN)
            break; /* sn_motor_parar */
        sn_tempo agora = sn_agora(m);

        for (size_t i = 2; i < c.n; i++)
            if (c.pf[i].revents)
                (c.fl[i]->tupla.protocolo == SN_PROTO_UDP ? sn_udp_socket : sn_tcp_socket)(
                    m, c.fl[i], c.pf[i].revents, agora);

        if (c.pf[1].revents & (POLLERR | POLLNVAL)) {
            ret = -1;
            break;
        }
        if (c.pf[1].revents & (POLLIN | POLLHUP)) {
            int fechou = 0;
            for (int k = 0; k < MAX_LIDOS_POR_VOLTA; k++) {
                ssize_t n = read(fd_tun, m->rx, sizeof m->rx);
                if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR)) {
                    fechou = 1; /* o outro lado do tun fechou */
                    break;
                }
                if (n < 0)
                    break;
                pacote_do_app(m, m->rx, (size_t)n, agora);
            }
            if (fechou) {
                ret = -1;
                break;
            }
        }
    }
    free(c.pf);
    free(c.fl);
    uint64_t lixo;
    ssize_t r = read(m->fd_parar, &lixo, sizeof lixo); /* zera o pedido de parada */
    (void)r;
    return ret;
}

/* No fim da gravação, quem ainda estava aberto sai com SN_FIM_SESSAO: o volume e a duração são
 * parciais (o app não fechou a conexão; quem cortou foi o Parar). */
static void saida_fim_de_sessao(void *ctx, sn_fluxo *f, uint8_t motivo) {
    (void)motivo;
    saida(ctx, f, SN_FIM_SESSAO);
}

void sn_motor_encerrar(sn_motor *m) {
    if (m->encerrado)
        return;
    m->encerrado = 1;
    sn_fluxos_destruir(m->fluxos, saida_fim_de_sessao, m);
    m->fluxos = NULL;
    sn_pcap_fechar(m->pcap);
    m->pcap = NULL;
    if (m->fd_tun >= 0)
        close(m->fd_tun);
    m->fd_tun = -1;
}

void sn_motor_destruir(sn_motor *m) {
    if (!m)
        return;
    sn_motor_encerrar(m);
    close(m->fd_parar);
    sn_fila_liberar(&m->fila);
    pthread_mutex_destroy(&m->mu_dns);
    free(m);
}

void sn_motor_trocar_dns(sn_motor *m, const sn_servidor *dns, int n) {
    n = limita(n, SN_MAX_DNS_REAIS);
    pthread_mutex_lock(&m->mu_dns);
    memcpy(m->c.dns_real, dns, (size_t)n * sizeof *dns);
    m->c.n_dns_real = n;
    pthread_mutex_unlock(&m->mu_dns);
}

static int eh_dns_virtual(const sn_motor *m, uint8_t versao, const uint8_t *ip) {
    for (int i = 0; i < m->c.n_dns_virtual; i++)
        if (m->c.dns_virtual[i].versao == versao &&
            memcmp(m->c.dns_virtual[i].ip, ip, versao == 4 ? 4 : 16) == 0)
            return 1;
    return 0;
}

int sn_destino_real(sn_motor *m, const sn_tupla *k, sn_endereco *dst, uint16_t *porta) {
    if (k->porta_destino == SN_PORTA_DNS && eh_dns_virtual(m, k->versao, k->ip_destino)) {
        pthread_mutex_lock(&m->mu_dns);
        int ok = m->c.n_dns_real > 0;
        if (ok) {
            *dst = m->c.dns_real[0].endereco;
            *porta = m->c.dns_real[0].porta;
        }
        pthread_mutex_unlock(&m->mu_dns);
        return ok ? 0 : -1;
    }
    dst->versao = k->versao;
    memcpy(dst->ip, k->ip_destino, 16);
    *porta = k->porta_destino;
    return 0;
}

int sn_anexa(uint8_t **buf, size_t *n, size_t *cap, const uint8_t *d, size_t k, size_t max) {
    if (*n + k > max)
        return -1;
    if (*n + k > *cap) {
        size_t novo = *cap ? *cap : 4096;
        while (novo < *n + k)
            novo *= 2;
        if (novo > max)
            novo = max;
        uint8_t *b = realloc(*buf, novo);
        if (!b)
            return -1;
        *buf = b;
        *cap = novo;
    }
    memcpy(*buf + *n, d, k);
    *n += k;
    return 0;
}
