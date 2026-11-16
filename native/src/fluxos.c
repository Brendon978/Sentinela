/* Tabela de fluxos: hash com encadeamento. Contrato em include/sn_fluxos.h.
 *
 * Cada fluxo é alocado sozinho (malloc), então o ponteiro não muda quando a tabela
 * cresce: o motor pode guardar o ponteiro junto do socket. A tabela é um vetor de
 * "baldes"; cada balde é uma lista ligada pelos campos `prox`. Quando a média passa de
 * 0,75 fluxo por balde, o vetor dobra e todos são redistribuídos.
 * Aula 02 (malloc/free, ponteiros) e 05 (por que o motor precisa disso).
 */
#include <stdlib.h>
#include <string.h>

#include "sn_fluxos.h"

enum { BALDES_INICIAIS = 1024 };

struct sn_fluxos {
    sn_fluxo **baldes;
    size_t n_baldes; /* sempre potência de 2: o índice é hash & (n_baldes - 1) */
    size_t n;
    uint32_t proximo_id;
};

/* FNV-1a de 32 bits sobre os campos da tupla, um a um (a struct pode ter bytes de
 * enchimento com lixo, então não se faz hash dela inteira). */
static uint32_t fnv(uint32_t h, const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

static uint32_t hash_tupla(const sn_tupla *k) {
    uint8_t portas[4] = {(uint8_t)(k->porta_origem >> 8), (uint8_t)k->porta_origem,
                         (uint8_t)(k->porta_destino >> 8), (uint8_t)k->porta_destino};
    uint32_t h = 2166136261u;
    h = fnv(h, &k->versao, 1);
    h = fnv(h, &k->protocolo, 1);
    h = fnv(h, k->ip_origem, 16);
    h = fnv(h, k->ip_destino, 16);
    return fnv(h, portas, 4);
}


sn_fluxos *sn_fluxos_criar(void) {
    sn_fluxos *t = calloc(1, sizeof *t);
    if (!t)
        return NULL;
    t->baldes = calloc(BALDES_INICIAIS, sizeof *t->baldes);
    if (!t->baldes) {
        free(t);
        return NULL;
    }
    t->n_baldes = BALDES_INICIAIS;
    t->proximo_id = 1;
    return t;
}

void sn_fluxos_destruir(sn_fluxos *t, sn_fluxo_saida saida, void *ctx) {
    if (!t)
        return;
    for (size_t b = 0; b < t->n_baldes; b++) {
        sn_fluxo *f = t->baldes[b];
        while (f) {
            sn_fluxo *prox = f->prox;
            if (saida)
                saida(ctx, f, SN_FIM_FECHADO);
            free(f);
            f = prox;
        }
    }
    free(t->baldes);
    free(t);
}

sn_fluxo *sn_fluxos_achar(const sn_fluxos *t, const sn_tupla *k) {
    for (sn_fluxo *f = t->baldes[hash_tupla(k) & (t->n_baldes - 1)]; f; f = f->prox)
        if (sn_tupla_igual(&f->tupla, k))
            return f;
    return NULL;
}

/* Dobra o número de baldes. Se faltar memória, segue com a tabela atual (só fica mais lenta). */
static void crescer(sn_fluxos *t) {
    size_t novo = t->n_baldes * 2;
    sn_fluxo **baldes = calloc(novo, sizeof *baldes);
    if (!baldes)
        return;
    for (size_t b = 0; b < t->n_baldes; b++) {
        sn_fluxo *f = t->baldes[b];
        while (f) {
            sn_fluxo *prox = f->prox;
            size_t i = hash_tupla(&f->tupla) & (novo - 1);
            f->prox = baldes[i];
            baldes[i] = f;
            f = prox;
        }
    }
    free(t->baldes);
    t->baldes = baldes;
    t->n_baldes = novo;
}

sn_fluxo *sn_fluxos_inserir(sn_fluxos *t, const sn_tupla *k, uint64_t agora_us) {
    sn_fluxo *f = calloc(1, sizeof *f);
    if (!f)
        return NULL;
    f->id = t->proximo_id++;
    f->tupla = *k;
    f->inicio_us = f->ultimo_us = agora_us;
    if (t->n + 1 > t->n_baldes / 4 * 3)
        crescer(t);
    size_t i = hash_tupla(k) & (t->n_baldes - 1);
    f->prox = t->baldes[i];
    t->baldes[i] = f;
    t->n++;
    return f;
}

/* Desliga f da lista do seu balde (sem liberar). */
static void desligar(sn_fluxos *t, sn_fluxo *f) {
    sn_fluxo **p = &t->baldes[hash_tupla(&f->tupla) & (t->n_baldes - 1)];
    while (*p && *p != f)
        p = &(*p)->prox;
    if (*p) {
        *p = f->prox;
        t->n--;
    }
}

void sn_fluxos_remover(sn_fluxos *t, sn_fluxo *f) {
    desligar(t, f);
    free(f);
}

/* Motivo de saída se o fluxo expirou em `agora`; -1 se continua. */
static int expirou(const sn_fluxo *f, uint64_t agora) {
    if (f->fechado)
        return agora - f->fechado_us >= SN_TCP_FECHADO_US ? f->motivo_fim : -1;
    uint64_t limite = f->tupla.protocolo == SN_PROTO_UDP ? SN_UDP_OCIOSO_US : SN_TCP_OCIOSO_US;
    return agora - f->ultimo_us >= limite ? SN_FIM_TEMPO : -1;
}

size_t sn_fluxos_expirar(sn_fluxos *t, uint64_t agora_us, sn_fluxo_saida saida, void *ctx) {
    size_t sairam = 0;
    for (size_t b = 0; b < t->n_baldes; b++) {
        sn_fluxo **p = &t->baldes[b];
        while (*p) {
            sn_fluxo *f = *p;
            int motivo = expirou(f, agora_us);
            if (motivo < 0) {
                p = &f->prox;
                continue;
            }
            *p = f->prox; /* desliga sem precisar procurar de novo */
            t->n--;
            if (saida)
                saida(ctx, f, (uint8_t)motivo);
            free(f);
            sairam++;
        }
    }
    return sairam;
}

size_t sn_fluxos_quantos(const sn_fluxos *t) { return t->n; }

void sn_fluxos_cada(const sn_fluxos *t, void (*fn)(void *ctx, sn_fluxo *f), void *ctx) {
    for (size_t b = 0; b < t->n_baldes; b++)
        for (sn_fluxo *f = t->baldes[b]; f; f = f->prox)
            fn(ctx, f);
}
