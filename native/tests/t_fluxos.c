/* Testes da Tarefa 5: tabela de fluxos com relógio controlado pelo teste. */
#include "sn_fluxos.h"
#include "teste.h"

static sn_tupla tupla(uint8_t proto, uint16_t porta_app, uint32_t servidor) {
    sn_tupla t = {.versao = 4, .protocolo = proto, .porta_origem = porta_app, .porta_destino = 443,
                  .ip_origem = {10, 111, 0, 1}};
    t.ip_destino[0] = (uint8_t)(servidor >> 24);
    t.ip_destino[1] = (uint8_t)(servidor >> 16);
    t.ip_destino[2] = (uint8_t)(servidor >> 8);
    t.ip_destino[3] = (uint8_t)servidor;
    return t;
}

typedef struct {
    int saidas;
    uint8_t ultimo_motivo;
    uint32_t ultimo_id;
} registro;

static void anota(void *ctx, sn_fluxo *f, uint8_t motivo) {
    registro *r = ctx;
    r->saidas++;
    r->ultimo_motivo = motivo;
    r->ultimo_id = f->id;
}

TESTE(fluxos_insere_acha_e_remove) {
    sn_fluxos *t = sn_fluxos_criar();
    sn_tupla a = tupla(SN_PROTO_TCP, 40000, 0x5db8d70e);
    CONFERE(sn_fluxos_achar(t, &a) == NULL);
    sn_fluxo *f = sn_fluxos_inserir(t, &a, 1000);
    CONFERE(f != NULL);
    CONFERE_IGUAL_INT(f->id, 1);
    CONFERE_IGUAL_INT(f->inicio_us, 1000);
    CONFERE_IGUAL_INT(f->ultimo_us, 1000);
    CONFERE(sn_fluxos_achar(t, &a) == f);
    CONFERE_IGUAL_INT(sn_fluxos_quantos(t), 1);

    sn_tupla b = a;
    b.porta_origem = 40001; /* outra porta do app = outro fluxo */
    CONFERE(sn_fluxos_achar(t, &b) == NULL);
    sn_fluxo *g = sn_fluxos_inserir(t, &b, 2000);
    CONFERE_IGUAL_INT(g->id, 2);

    sn_fluxos_remover(t, f);
    CONFERE(sn_fluxos_achar(t, &a) == NULL);
    CONFERE(sn_fluxos_achar(t, &b) == g);
    CONFERE_IGUAL_INT(sn_fluxos_quantos(t), 1);
    sn_fluxos_destruir(t, NULL, NULL);
}

TESTE(fluxos_protocolo_e_versao_fazem_parte_da_chave) {
    sn_fluxos *t = sn_fluxos_criar();
    sn_tupla tcp = tupla(SN_PROTO_TCP, 40000, 1);
    sn_tupla udp = tupla(SN_PROTO_UDP, 40000, 1);
    sn_fluxos_inserir(t, &tcp, 0);
    CONFERE(sn_fluxos_achar(t, &udp) == NULL);
    sn_tupla v6 = tcp;
    v6.versao = 6;
    CONFERE(sn_fluxos_achar(t, &v6) == NULL);
    sn_fluxos_destruir(t, NULL, NULL);
}

TESTE(fluxos_dez_mil_com_crescimento) {
    sn_fluxos *t = sn_fluxos_criar();
    for (uint32_t i = 0; i < 10000; i++) {
        sn_tupla k = tupla(i % 2 ? SN_PROTO_TCP : SN_PROTO_UDP, (uint16_t)(30000 + i % 30000), i);
        if (!sn_fluxos_inserir(t, &k, i)) {
            CONFERE(0);
        }
    }
    CONFERE_IGUAL_INT(sn_fluxos_quantos(t), 10000);
    for (uint32_t i = 0; i < 10000; i++) {
        sn_tupla k = tupla(i % 2 ? SN_PROTO_TCP : SN_PROTO_UDP, (uint16_t)(30000 + i % 30000), i);
        sn_fluxo *f = sn_fluxos_achar(t, &k);
        if (!f || f->id != i + 1) {
            fprintf(stderr, "  fluxo %u perdido depois do crescimento\n", i);
            CONFERE(0);
        }
    }
    sn_fluxos_destruir(t, NULL, NULL);
}

TESTE(fluxos_udp_expira_aos_60s_sem_trafego) {
    sn_fluxos *t = sn_fluxos_criar();
    sn_tupla k = tupla(SN_PROTO_UDP, 40000, 1);
    sn_fluxos_inserir(t, &k, 0);
    registro r = {0};
    CONFERE_IGUAL_INT(sn_fluxos_expirar(t, SN_UDP_OCIOSO_US - 1, anota, &r), 0);
    CONFERE_IGUAL_INT(sn_fluxos_expirar(t, SN_UDP_OCIOSO_US, anota, &r), 1);
    CONFERE_IGUAL_INT(r.saidas, 1);
    CONFERE_IGUAL_INT(r.ultimo_motivo, SN_FIM_TEMPO);
    CONFERE(sn_fluxos_achar(t, &k) == NULL);
    sn_fluxos_destruir(t, NULL, NULL);
}

TESTE(fluxos_trafego_adia_a_expiracao) {
    sn_fluxos *t = sn_fluxos_criar();
    sn_tupla k = tupla(SN_PROTO_UDP, 40000, 1);
    sn_fluxo *f = sn_fluxos_inserir(t, &k, 0);
    f->ultimo_us = 50 * 1000000ull;
    registro r = {0};
    CONFERE_IGUAL_INT(sn_fluxos_expirar(t, 100 * 1000000ull, anota, &r), 0);
    CONFERE_IGUAL_INT(sn_fluxos_expirar(t, 110 * 1000000ull, anota, &r), 1);
    sn_fluxos_destruir(t, NULL, NULL);
}

TESTE(fluxos_tcp_fechado_sai_depois_de_10s_com_o_motivo) {
    sn_fluxos *t = sn_fluxos_criar();
    sn_tupla k = tupla(SN_PROTO_TCP, 40000, 1);
    sn_fluxo *f = sn_fluxos_inserir(t, &k, 0);
    f->fechado = 1;
    f->fechado_us = 5 * 1000000ull;
    f->motivo_fim = SN_FIM_RESET;
    registro r = {0};
    CONFERE_IGUAL_INT(sn_fluxos_expirar(t, 5 * 1000000ull + SN_TCP_FECHADO_US - 1, anota, &r), 0);
    CONFERE_IGUAL_INT(sn_fluxos_expirar(t, 5 * 1000000ull + SN_TCP_FECHADO_US, anota, &r), 1);
    CONFERE_IGUAL_INT(r.ultimo_motivo, SN_FIM_RESET);
    sn_fluxos_destruir(t, NULL, NULL);
}

TESTE(fluxos_tcp_aberto_aguenta_ate_2h) {
    sn_fluxos *t = sn_fluxos_criar();
    sn_tupla k = tupla(SN_PROTO_TCP, 40000, 1);
    sn_fluxos_inserir(t, &k, 0);
    registro r = {0};
    CONFERE_IGUAL_INT(sn_fluxos_expirar(t, SN_UDP_OCIOSO_US * 10, anota, &r), 0);
    CONFERE_IGUAL_INT(sn_fluxos_expirar(t, SN_TCP_OCIOSO_US - 1, anota, &r), 0);
    CONFERE_IGUAL_INT(sn_fluxos_expirar(t, SN_TCP_OCIOSO_US, anota, &r), 1);
    CONFERE_IGUAL_INT(r.ultimo_motivo, SN_FIM_TEMPO);
    sn_fluxos_destruir(t, NULL, NULL);
}

TESTE(fluxos_destruir_avisa_os_restantes) {
    sn_fluxos *t = sn_fluxos_criar();
    for (uint32_t i = 0; i < 5; i++) {
        sn_tupla k = tupla(SN_PROTO_TCP, (uint16_t)(40000 + i), 1);
        sn_fluxos_inserir(t, &k, 0);
    }
    registro r = {0};
    sn_fluxos_destruir(t, anota, &r);
    CONFERE_IGUAL_INT(r.saidas, 5);
}

static void conta(void *ctx, sn_fluxo *f) {
    (void)f;
    (*(int *)ctx)++;
}

TESTE(fluxos_cada_visita_todos) {
    sn_fluxos *t = sn_fluxos_criar();
    for (uint32_t i = 0; i < 300; i++) {
        sn_tupla k = tupla(SN_PROTO_UDP, (uint16_t)(40000 + i), 1);
        sn_fluxos_inserir(t, &k, 0);
    }
    int n = 0;
    sn_fluxos_cada(t, conta, &n);
    CONFERE_IGUAL_INT(n, 300);
    sn_fluxos_destruir(t, NULL, NULL);
}
