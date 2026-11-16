/* Relé UDP: cada fluxo UDP do app ganha um socket real conectado ao destino. O que o app
 * manda vai pelo socket; o que volta é remontado como pacote IP/UDP e escrito no tun, com
 * os endereços que o app espera (inclusive o DNS virtual). Aula 05, seção 7. */
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "motor_interno.h"

enum { PORTA_QUIC = 443, MAX_RECEBIDOS = 64 };

typedef struct {
    sn_estado base;
    int eh_dns; /* respostas passam pelo parser de DNS */
} estado_udp;

static sn_fluxo *novo_fluxo(sn_motor *m, const sn_tupla *k, sn_tempo agora) {
    sn_endereco destino;
    uint16_t porta;
    if (sn_destino_real(m, k, &destino, &porta) != 0)
        return NULL; /* DNS virtual sem DNS real: sem resposta */
    estado_udp *e = calloc(1, sizeof *e);
    if (!e)
        return NULL;
    e->base.fd = sn_socket_para(&destino, porta, SOCK_DGRAM);
    if (e->base.fd < 0) {
        free(e);
        return NULL;
    }
    e->base.eventos = POLLIN;
    e->eh_dns = k->porta_destino == SN_PORTA_DNS;
    sn_fluxo *f = sn_novo_fluxo(m, k, agora);
    if (!f) {
        close(e->base.fd);
        free(e);
        return NULL;
    }
    f->estado = e;
    sn_ev_fluxo_novo(m, f);
    return f;
}

void sn_udp_do_app(sn_motor *m, const sn_ip *ip, const uint8_t *pkt, sn_tempo agora) {
    const uint8_t *l4 = pkt + ip->tam_cabecalho;
    sn_udp u;
    if (sn_udp_ler(l4, ip->tam_total - ip->tam_cabecalho, &u) != SN_OK)
        return;
    if (m->c.forcar_tcp && u.porta_destino == PORTA_QUIC)
        return; /* sem resposta: o app desiste do QUIC e tenta TCP */

    sn_tupla k = sn_tupla_de(ip, SN_PROTO_UDP, u.porta_origem, u.porta_destino);
    sn_fluxo *f = sn_fluxos_achar(m->fluxos, &k);
    if (f && f->fechado)
        return;
    if (!f && !(f = novo_fluxo(m, &k, agora)))
        return;

    size_t n = u.tamanho - 8u;
    estado_udp *e = f->estado;
    if (send(e->base.fd, l4 + 8, n, 0) < 0)
        return; /* buffer cheio ou rede fora: UDP pode perder */
    f->bytes_env += n;
    f->pacotes++;
    f->ultimo_us = agora.mono;
    e->base.alterado = 1;
}

void sn_udp_socket(sn_motor *m, sn_fluxo *f, short revents, sn_tempo agora) {
    estado_udp *e = f->estado;
    if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
        /* ex.: ICMP "porta inalcançável" vira erro no socket conectado; consome e segue */
        int err;
        socklen_t tam = sizeof err;
        getsockopt(e->base.fd, SOL_SOCKET, SO_ERROR, &err, &tam);
    }
    if (!(revents & POLLIN))
        return;
    /* A resposta volta "de onde o app mandou" (ex.: o DNS virtual), para o app. */
    sn_tupla volta = sn_tupla_inversa(&f->tupla);

    for (int k = 0; k < MAX_RECEBIDOS; k++) {
        ssize_t n = recv(e->base.fd, m->rx, sizeof m->rx, 0);
        if (n < 0)
            break; /* EAGAIN: acabou; outros erros: tenta na próxima */
        size_t tam = sn_montar_udp(m->tx, sizeof m->tx, &volta, m->rx, (size_t)n);
        if (tam == 0 || sn_escrever_tun(m, m->tx, tam, agora) != 0)
            continue;
        f->bytes_rec += (uint64_t)n;
        f->pacotes++;
        f->ultimo_us = agora.mono;
        e->base.alterado = 1;
        if (e->eh_dns) {
            sn_dns_resposta r;
            if (sn_dns_ler_resposta(m->rx, (size_t)n, &r) == SN_OK && r.n_enderecos > 0)
                sn_ev_dns(m, &r);
        }
    }
}
