#include "banca.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "sn_nomes.h"
#include "teste.h"

static uint64_t relogio_falso(void *ctx) {
    sn_banca *b = ctx;
    pthread_mutex_lock(&b->mu);
    uint64_t t = b->agora_us;
    pthread_mutex_unlock(&b->mu);
    return t;
}

static uint64_t relogio_mono_falso(void *ctx) {
    sn_banca *b = ctx;
    pthread_mutex_lock(&b->mu);
    uint64_t t = b->mono_us;
    pthread_mutex_unlock(&b->mu);
    return t;
}

void banca_avancar(sn_banca *b, uint64_t us) {
    pthread_mutex_lock(&b->mu);
    b->agora_us += us;
    b->mono_us += us;
    pthread_mutex_unlock(&b->mu);
}

void banca_ajustar_hora(sn_banca *b, int64_t us) {
    pthread_mutex_lock(&b->mu);
    b->agora_us = (uint64_t)((int64_t)b->agora_us + us);
    pthread_mutex_unlock(&b->mu);
}

static void *roda(void *arg) {
    sn_banca *b = arg;
    int fds_motor = b->ret; /* passado pelo campo ret na partida */
    b->ret = sn_motor_rodar(b->m, fds_motor);
    return NULL;
}

int banca_iniciar(sn_banca *b, sn_config *c) {
    memset(b, 0, sizeof *b);
    pthread_mutex_init(&b->mu, NULL);
    b->agora_us = 1700000000ull * 1000000ull;
    b->mono_us = 5000000000ull; /* monotônico começa num valor qualquer */
    c->relogio_us = relogio_falso;
    c->relogio_mono_us = relogio_mono_falso;
    c->relogio_ctx = b;
    int par[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, par) != 0)
        return -1;
    b->app_fd = par[0];
    b->m = sn_motor_criar(c);
    if (!b->m) {
        close(par[0]);
        close(par[1]);
        return -1;
    }
    b->ret = par[1];
    if (pthread_create(&b->thread, NULL, roda, b) != 0)
        return -1;
    b->rodando = 1;
    return 0;
}

void banca_parar(sn_banca *b) {
    if (!b->rodando)
        return;
    sn_motor_parar(b->m);
    pthread_join(b->thread, NULL);
    b->rodando = 0;
    sn_motor_encerrar(b->m);
}

void banca_fim(sn_banca *b) {
    banca_parar(b);
    sn_motor_destruir(b->m);
    close(b->app_fd);
    pthread_mutex_destroy(&b->mu);
}

int banca_enviar(sn_banca *b, const uint8_t *p, size_t n) {
    return send(b->app_fd, p, n, 0) == (ssize_t)n ? 0 : -1;
}

ssize_t banca_receber(sn_banca *b, uint8_t *buf, size_t cap, int ms) {
    struct pollfd pf = {.fd = b->app_fd, .events = POLLIN};
    if (poll(&pf, 1, ms) <= 0)
        return -1;
    return recv(b->app_fd, buf, cap, 0);
}

uint16_t le16_ev(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
uint32_t le32_ev(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
uint64_t le64_ev(const uint8_t *p) { return le32_ev(p) | (uint64_t)le32_ev(p + 4) << 32; }

static void drena(sn_banca *b) {
    b->n_eventos += sn_motor_eventos(b->m, b->eventos + b->n_eventos, sizeof b->eventos - b->n_eventos);
}

static const uint8_t *procura(sn_banca *b, uint8_t tipo, size_t *de, uint16_t *tam) {
    size_t i = *de;
    while (i + 3 <= b->n_eventos) {
        uint16_t t = le16_ev(b->eventos + i + 1);
        if (i + 3 + t > b->n_eventos)
            break;
        if (b->eventos[i] == tipo) {
            *tam = t;
            *de = i + 3 + t;
            return b->eventos + i + 3;
        }
        i += 3 + (size_t)t;
    }
    return NULL;
}

const uint8_t *banca_evento(sn_banca *b, uint8_t tipo, size_t *de, uint16_t *tam, int ms) {
    for (int esperou = 0;; esperou += 10) {
        drena(b);
        const uint8_t *e = procura(b, tipo, de, tam);
        if (e || esperou >= ms)
            return e;
        struct timespec ts = {0, 10 * 1000 * 1000};
        nanosleep(&ts, NULL); /* estavel: intervalo de sondagem da fila, com teto BANCA_TETO_MS */
    }
}

int banca_conta(sn_banca *b, uint8_t tipo) {
    drena(b);
    int n = 0;
    size_t de = 0;
    uint16_t tam;
    while (procura(b, tipo, &de, &tam))
        n++;
    return n;
}

/* ---------------------------------------------------------------- servidores locais */

static void *serve(void *arg) {
    sn_servidor_teste *s = arg;
    uint8_t buf[65536];
    uint8_t resposta[1024];
    size_t n_resposta = 0;
    const uint8_t *dns_payload = NULL;
    if (s->dns) {
        uint8_t p[512];
        size_t n = sn_fixture("dns_cname_a", p, sizeof p);
        /* payload DNS = depois de IP (20) + UDP (8) */
        n_resposta = n - 28;
        memcpy(resposta, p + 28, n_resposta);
        dns_payload = resposta;
    }
    while (!__atomic_load_n(&s->parar, __ATOMIC_SEQ_CST)) {
        struct pollfd pf = {.fd = s->fd, .events = POLLIN};
        if (poll(&pf, 1, 50) <= 0)
            continue;
        struct sockaddr_storage de;
        socklen_t tam = sizeof de;
        ssize_t n = recvfrom(s->fd, buf, sizeof buf, 0, (struct sockaddr *)&de, &tam);
        if (n < 0)
            continue;
        if (dns_payload && n >= 2) {
            resposta[0] = buf[0]; /* mesmo id da consulta */
            resposta[1] = buf[1];
            sendto(s->fd, resposta, n_resposta, 0, (struct sockaddr *)&de, tam);
        } else {
            sendto(s->fd, buf, (size_t)n, 0, (struct sockaddr *)&de, tam);
        }
    }
    return NULL;
}

int servidor_udp_iniciar(sn_servidor_teste *s, int versao, int dns) {
    memset(s, 0, sizeof *s);
    s->dns = dns;
    if (versao == 4) {
        struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        s->fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (s->fd < 0 || bind(s->fd, (struct sockaddr *)&a, sizeof a) != 0)
            return -1;
        socklen_t t = sizeof a;
        getsockname(s->fd, (struct sockaddr *)&a, &t);
        s->porta = ntohs(a.sin_port);
    } else {
        struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
        s->fd = socket(AF_INET6, SOCK_DGRAM, 0);
        if (s->fd < 0 || bind(s->fd, (struct sockaddr *)&a, sizeof a) != 0)
            return -1;
        socklen_t t = sizeof a;
        getsockname(s->fd, (struct sockaddr *)&a, &t);
        s->porta = ntohs(a.sin6_port);
    }
    return pthread_create(&s->thread, NULL, serve, s) == 0 ? 0 : -1;
}

void servidor_udp_parar(sn_servidor_teste *s) {
    __atomic_store_n(&s->parar, 1, __ATOMIC_SEQ_CST);
    pthread_join(s->thread, NULL);
    close(s->fd);
}
