/* Fila de eventos do motor para o Kotlin (formato C2). Uma thread põe (o motor), outra
 * tira (o app), então tudo passa por um mutex. Aula 05 (laço de eventos). */
#include <stdlib.h>
#include <string.h>

#include "bytes.h"
#include "motor_interno.h"

int sn_fila_iniciar(sn_fila *f) {
    memset(f, 0, sizeof *f);
    return pthread_mutex_init(&f->mu, NULL);
}

void sn_fila_liberar(sn_fila *f) {
    free(f->buf);
    pthread_mutex_destroy(&f->mu);
}

void sn_fila_por(sn_fila *f, uint8_t tipo, const uint8_t *corpo, uint16_t n) {
    uint8_t reg[3 + UINT16_MAX];
    reg[0] = tipo;
    put_le16(reg + 1, n);
    memcpy(reg + 3, corpo, n);
    pthread_mutex_lock(&f->mu);
    if (sn_anexa(&f->buf, &f->n, &f->cap, reg, 3 + (size_t)n, SN_FILA_MAX) != 0)
        f->perdidos++; /* fila cheia (ou sem memória): avisa com SN_EV_PERDA */
    pthread_mutex_unlock(&f->mu);
}

size_t sn_fila_tirar(sn_fila *f, uint8_t *dst, size_t cap) {
    size_t escrito = 0;
    pthread_mutex_lock(&f->mu);
    if (f->perdidos && cap < 7) { /* o aviso de perda tem de vir antes de tudo */
        pthread_mutex_unlock(&f->mu);
        return 0;
    }
    if (f->perdidos) {
        dst[0] = SN_EV_PERDA;
        put_le16(dst + 1, 4);
        put_le32(dst + 3, f->perdidos);
        escrito = 7;
        f->perdidos = 0;
    }
    /* só registros inteiros */
    size_t i = 0;
    while (i + 3 <= f->n) {
        size_t tam = 3 + (size_t)(f->buf[i + 1] | f->buf[i + 2] << 8); /* u16 little-endian */
        if (escrito + tam > cap)
            break;
        memcpy(dst + escrito, f->buf + i, tam);
        escrito += tam;
        i += tam;
    }
    if (i) { /* com a fila nunca usada, buf ainda é NULL */
        memmove(f->buf, f->buf + i, f->n - i);
        f->n -= i;
    }
    pthread_mutex_unlock(&f->mu);
    return escrito;
}

/* ---------------------------------------------------------------- montagem dos eventos */

/* Escrevem e devolvem quantos bytes ocuparam, para encadear: i += p32(c + i, v). */
static size_t p16(uint8_t *d, uint32_t v) { put_le16(d, v); return 2; }
static size_t p32(uint8_t *d, uint32_t v) { put_le32(d, v); return 4; }
static size_t p64(uint8_t *d, uint64_t v) { put_le64(d, v); return 8; }

void sn_ev_fluxo_novo(sn_motor *m, const sn_fluxo *f) {
    uint8_t c[64];
    size_t i = p32(c, f->id);
    c[i++] = f->tupla.versao;
    c[i++] = f->tupla.protocolo;
    memcpy(c + i, f->tupla.ip_origem, 16);
    i += 16;
    i += p16(c + i, f->tupla.porta_origem);
    memcpy(c + i, f->tupla.ip_destino, 16);
    i += 16;
    i += p16(c + i, f->tupla.porta_destino);
    i += p64(c + i, f->inicio_us);
    sn_fila_por(&m->fila, SN_EV_FLUXO_NOVO, c, (uint16_t)i);
}

void sn_ev_bytes(sn_motor *m, const sn_fluxo *f) {
    uint8_t c[24];
    size_t i = p32(c, f->id);
    i += p64(c + i, f->bytes_env);
    i += p64(c + i, f->bytes_rec);
    i += p32(c + i, f->pacotes);
    sn_fila_por(&m->fila, SN_EV_FLUXO_BYTES, c, (uint16_t)i);
}

void sn_ev_fim(sn_motor *m, const sn_fluxo *f, uint64_t fim_us, uint8_t motivo) {
    uint8_t c[13];
    size_t i = p32(c, f->id);
    i += p64(c + i, fim_us);
    c[i++] = motivo;
    sn_fila_por(&m->fila, SN_EV_FLUXO_FIM, c, (uint16_t)i);
}

void sn_ev_dns(sn_motor *m, const sn_dns_resposta *r) {
    uint8_t c[2 + SN_DNS_MAX_ENDERECOS * 17 + 2 + SN_NOME_MAX];
    size_t n_ips = (size_t)r->n_enderecos;
    size_t i = p16(c, (uint32_t)n_ips);
    for (size_t k = 0; k < n_ips; k++)
        c[i++] = r->enderecos[k].versao;
    for (size_t k = 0; k < n_ips; k++) {
        memcpy(c + i, r->enderecos[k].ip, 16);
        i += 16;
    }
    size_t tam = strlen(r->nome);
    i += p16(c + i, (uint32_t)tam);
    memcpy(c + i, r->nome, tam);
    i += tam;
    sn_fila_por(&m->fila, SN_EV_DNS, c, (uint16_t)i);
}

void sn_ev_sni(sn_motor *m, const sn_fluxo *f, const char *nome, int ech) {
    uint8_t c[4 + 2 + SN_NOME_MAX + 1];
    size_t tam = strlen(nome);
    if (tam > SN_NOME_MAX)
        tam = SN_NOME_MAX;
    size_t i = p32(c, f->id);
    i += p16(c + i, (uint32_t)tam);
    memcpy(c + i, nome, tam);
    i += tam;
    c[i++] = ech ? 1 : 0;
    sn_fila_por(&m->fila, SN_EV_SNI, c, (uint16_t)i);
}
