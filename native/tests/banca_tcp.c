#include "banca_tcp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const uint8_t APP[16] = {10, 111, 0, 1};
static const uint8_t LO[16] = {127, 0, 0, 1};

static int depois(uint32_t a, uint32_t b) { return (int32_t)(a - b) > 0; } /* a > b em mod 2^32 */

uint8_t dado(size_t i) { return (uint8_t)(i * 31 + 7); }

uint64_t fnv64(uint64_t h, const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h;
}

void cli_iniciar(sn_cliente *c, uint16_t porta_app, uint16_t porta_servidor) {
    memset(c, 0, sizeof *c);
    c->t.versao = 4;
    c->t.protocolo = SN_PROTO_TCP;
    memcpy(c->t.ip_origem, APP, 16);
    memcpy(c->t.ip_destino, LO, 16);
    c->t.porta_origem = porta_app;
    c->t.porta_destino = porta_servidor;
    c->seq = 1000000;
    c->janela = 65535;
}

void cli_liberar(sn_cliente *c) { free(c->rx); }

int cli_segmento(sn_banca *b, sn_cliente *c, uint32_t seq, uint8_t flags, const void *dados, size_t n) {
    uint8_t pkt[2048];
    size_t tam = sn_montar_tcp(pkt, sizeof pkt, &c->t, seq, c->ack, flags, c->janela,
                               (flags & SN_TCP_SYN) ? 1400 : 0, dados, n);
    return tam ? banca_enviar(b, pkt, tam) : -1;
}

static void guarda(sn_cliente *c, const uint8_t *d, size_t n) {
    if (c->n_rx + n > c->cap_rx) {
        size_t novo = c->cap_rx ? c->cap_rx : 4096;
        while (novo < c->n_rx + n)
            novo *= 2;
        c->rx = realloc(c->rx, novo);
        c->cap_rx = novo;
    }
    memcpy(c->rx + c->n_rx, d, n);
    c->n_rx += n;
}

int cli_processa(sn_banca *b, sn_cliente *c, int ms) {
    uint8_t pkt[70000];
    ssize_t n = banca_receber(b, pkt, sizeof pkt, ms);
    if (n <= 0)
        return 0;
    sn_ip ip;
    sn_tcp t;
    if (sn_ip_ler(pkt, (size_t)n, &ip) != SN_OK || ip.protocolo != SN_PROTO_TCP ||
        sn_tcp_ler(pkt + ip.tam_cabecalho, ip.tam_total - ip.tam_cabecalho, &t) != SN_OK ||
        !sn_transporte_checksum_ok(pkt, &ip))
        return 1;
    if (t.flags & SN_TCP_RST) {
        c->rst_recebido = 1;
        return 1;
    }
    if (t.flags & SN_TCP_SYN) {
        c->flags_synack = t.flags;
        c->ack = t.seq + 1;
        c->mss_motor = t.mss;
    }
    if (t.flags & SN_TCP_ACK) {
        if (depois(t.ack, c->confirmado) || c->confirmado == 0)
            c->confirmado = t.ack;
        c->janela_motor = t.janela;
    }
    size_t len = ip.tam_total - ip.tam_cabecalho - t.tam_cabecalho;
    const uint8_t *d = pkt + ip.tam_cabecalho + t.tam_cabecalho;
    int responder = 0;
    if (len == 0 && !(t.flags & (SN_TCP_SYN | SN_TCP_FIN)))
        c->acks_recebidos++;
    if (len == 0 && !(t.flags & (SN_TCP_SYN | SN_TCP_FIN)) && t.seq != c->ack && c->ack != 0)
        responder = 1; /* sonda (keepalive/janela zero): responde com ACK, como manda a RFC */
    if (len) {
        c->segs_dados++;
        c->bytes_vistos += len;
        if (c->descartar && c->segs_dados == c->descartar)
            return 1; /* "perdido" no caminho */
        if (t.seq == c->ack && len <= c->janela) {
            guarda(c, d, len);
            c->ack += (uint32_t)len;
            /* junta o que estava esperando o buraco fechar */
            for (int achou = 1; achou;) {
                achou = 0;
                for (int i = 0; i < c->n_ooo; i++) {
                    uint32_t ini = c->ooo[i].seq, fim = ini + (uint32_t)c->ooo[i].n;
                    if (!depois(ini, c->ack) && depois(fim, c->ack)) {
                        size_t pula = c->ack - ini;
                        guarda(c, c->ooo[i].d + pula, c->ooo[i].n - pula);
                        c->ack = fim;
                    }
                    if (!depois(fim, c->ack)) {
                        c->ooo[i] = c->ooo[--c->n_ooo];
                        achou = 1;
                        break;
                    }
                }
            }
        } else if (depois(t.seq, c->ack) && c->n_ooo < 64 && len <= sizeof c->ooo[0].d) {
            c->ooo[c->n_ooo].seq = t.seq;
            c->ooo[c->n_ooo].n = len;
            memcpy(c->ooo[c->n_ooo].d, d, len);
            c->n_ooo++;
        }
        responder = 1;
    }
    if ((t.flags & SN_TCP_FIN) && t.seq + len == c->ack) {
        c->ack += 1;
        c->fin_recebido = 1;
        responder = 1;
    }
    if (responder)
        cli_segmento(b, c, c->seq, SN_TCP_ACK, NULL, 0);
    return 1;
}

int cli_conectar(sn_banca *b, sn_cliente *c) {
    if (cli_segmento(b, c, c->seq, SN_TCP_SYN, NULL, 0) != 0)
        return -1;
    c->seq++;
    for (int i = 0; i < 20 && !c->flags_synack && !c->rst_recebido; i++)
        if (!cli_processa(b, c, BANCA_TETO_MS))
            break;
    if (c->rst_recebido || c->flags_synack != (SN_TCP_SYN | SN_TCP_ACK))
        return -1;
    return cli_segmento(b, c, c->seq, SN_TCP_ACK, NULL, 0);
}

int cli_enviar(sn_banca *b, sn_cliente *c, const void *dados, size_t n) {
    const uint8_t *p = dados;
    uint32_t inicio = c->seq;
    size_t enviado = 0;
    while (enviado < n) {
        uint32_t em_voo = c->seq - c->confirmado;
        if (em_voo >= c->janela_motor) {
            if (!cli_processa(b, c, BANCA_TETO_MS))
                return -1; /* motor parou de confirmar */
            continue;
        }
        size_t pedaco = n - enviado;
        if (pedaco > 1400) pedaco = 1400;
        if (pedaco > c->janela_motor - em_voo) pedaco = c->janela_motor - em_voo;
        if (cli_segmento(b, c, c->seq, SN_TCP_ACK | SN_TCP_PSH, p + enviado, pedaco) != 0)
            return -1;
        c->seq += (uint32_t)pedaco;
        enviado += pedaco;
    }
    while (depois(inicio + (uint32_t)n, c->confirmado))
        if (!cli_processa(b, c, BANCA_TETO_MS))
            return -1;
    return 0;
}

int cli_receber(sn_banca *b, sn_cliente *c, size_t n) {
    while (!c->fin_recebido && !c->rst_recebido && (n == 0 || c->n_rx < n))
        if (!cli_processa(b, c, BANCA_TETO_MS))
            return -1;
    return 0;
}

int cli_fin(sn_banca *b, sn_cliente *c) {
    int r = cli_segmento(b, c, c->seq, SN_TCP_FIN | SN_TCP_ACK, NULL, 0);
    c->seq++;
    return r;
}

/* ---------------------------------------------------------------- servidores */

static void *serve_tcp(void *arg) {
    sn_servidor_tcp *s = arg;
    int cli = accept(s->fd, NULL, NULL);
    if (cli < 0)
        return NULL;
    s->hash = FNV64_INICIO;
    uint8_t buf[65536];
    if (s->modo == SRV_FONTE) {
        size_t i = 0;
        while (i < s->n_fonte) {
            size_t k = 0;
            for (; k < sizeof buf && i + k < s->n_fonte; k++)
                buf[k] = dado(i + k);
            ssize_t w = send(cli, buf, k, MSG_NOSIGNAL);
            if (w <= 0)
                break;
            i += (size_t)w;
        }
        close(cli);
        return NULL;
    }
    for (;;) {
        ssize_t r = recv(cli, buf, sizeof buf, 0);
        if (r < 0 && errno == ECONNRESET)
            s->erro_reset = 1;
        if (r <= 0)
            break;
        s->recebidos += (uint64_t)r;
        s->hash = fnv64(s->hash, buf, (size_t)r);
        if (s->modo == SRV_ECO && send(cli, buf, (size_t)r, MSG_NOSIGNAL) != r)
            break;
    }
    if (s->modo == SRV_SUMIDOURO) {
        uint8_t res[16];
        memcpy(res, &s->recebidos, 8);
        memcpy(res + 8, &s->hash, 8);
        send(cli, res, sizeof res, MSG_NOSIGNAL);
    }
    close(cli);
    return NULL;
}

int servidor_tcp_iniciar(sn_servidor_tcp *s, int modo) {
    size_t n_fonte = s->n_fonte;
    memset(s, 0, sizeof *s);
    s->modo = modo;
    s->n_fonte = n_fonte;
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    s->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s->fd < 0 || bind(s->fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(s->fd, 4) != 0)
        return -1;
    socklen_t t = sizeof a;
    getsockname(s->fd, (struct sockaddr *)&a, &t);
    s->porta = ntohs(a.sin_port);
    return pthread_create(&s->thread, NULL, serve_tcp, s) == 0 ? 0 : -1;
}

void servidor_tcp_esperar(sn_servidor_tcp *s) {
    /* Se o teste falhou antes de conectar, o accept ficaria preso: shutdown o acorda. */
    shutdown(s->fd, SHUT_RDWR);
    pthread_join(s->thread, NULL);
    close(s->fd);
}

uint16_t porta_fechada(void) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    bind(fd, (struct sockaddr *)&a, sizeof a);
    socklen_t t = sizeof a;
    getsockname(fd, (struct sockaddr *)&a, &t);
    close(fd);
    return ntohs(a.sin_port);
}
