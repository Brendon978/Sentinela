/* Bancada TCP: um mini cliente TCP que faz o papel do app (fala com o motor pelo tun
 * falso, montando os segmentos à mão) e servidores TCP locais de verdade. */
#ifndef BANCA_TCP_H
#define BANCA_TCP_H

#include "banca.h"

typedef struct {
    sn_tupla t;          /* app -> servidor */
    uint32_t seq;        /* próximo seq nosso */
    uint32_t ack;        /* próximo seq esperado do motor */
    uint32_t confirmado; /* maior ack recebido do motor */
    uint32_t janela_motor;
    uint16_t janela;     /* janela que anunciamos */
    uint16_t mss_motor;
    uint8_t *rx;         /* dados recebidos do motor, em ordem */
    size_t n_rx, cap_rx;
    int fin_recebido;
    int rst_recebido;
    uint8_t flags_synack;
    /* Como o Linux: guarda segmentos fora de ordem e junta quando o buraco fecha. */
    struct { uint32_t seq; size_t n; uint8_t d[1500]; } ooo[64];
    int n_ooo;
    int descartar;         /* descarta o N-ésimo segmento de dados recebido (0 = nenhum) */
    int segs_dados;        /* segmentos de dados recebidos */
    uint64_t bytes_vistos; /* soma dos dados de todos os segmentos recebidos (com repetições) */
    int acks_recebidos;    /* segmentos só de ACK (sem dados, sem SYN/FIN/RST) */
} sn_cliente;

void cli_iniciar(sn_cliente *c, uint16_t porta_app, uint16_t porta_servidor);
void cli_liberar(sn_cliente *c);
/* Manda um segmento cru (sem esperar nada). */
int cli_segmento(sn_banca *b, sn_cliente *c, uint32_t seq, uint8_t flags, const void *dados, size_t n);
/* Lê e processa um pacote do motor (dados, ACK, FIN, RST); responde ACK a dados/FIN.
 * Devolve 1 se leu algo, 0 no tempo esgotado. */
int cli_processa(sn_banca *b, sn_cliente *c, int ms);
/* SYN -> SYN-ACK -> ACK. 0 se conectou, -1 se recebeu RST ou nada. */
int cli_conectar(sn_banca *b, sn_cliente *c);
/* Envia respeitando a janela do motor e espera tudo ser confirmado. */
int cli_enviar(sn_banca *b, sn_cliente *c, const void *dados, size_t n);
/* Processa pacotes até ter `n` bytes em rx ou receber FIN (n = 0: até o FIN). */
int cli_receber(sn_banca *b, sn_cliente *c, size_t n);
int cli_fin(sn_banca *b, sn_cliente *c);

enum { SRV_ECO, SRV_SUMIDOURO, SRV_FONTE };

typedef struct {
    int fd;
    uint16_t porta;
    int modo;
    size_t n_fonte;       /* SRV_FONTE: quantos bytes manda */
    pthread_t thread;
    /* resultado (lido depois do join) */
    uint64_t recebidos;
    uint64_t hash;        /* FNV-1a 64 do que recebeu */
    int erro_reset;       /* recv deu ECONNRESET */
} sn_servidor_tcp;

int servidor_tcp_iniciar(sn_servidor_tcp *s, int modo);
void servidor_tcp_esperar(sn_servidor_tcp *s); /* join (a conversa termina sozinha) */
/* Uma porta local onde ninguém escuta (conexão recusada). */
uint16_t porta_fechada(void);

/* Dados determinísticos e o hash usado nos dois lados. */
uint8_t dado(size_t i);
uint64_t fnv64(uint64_t h, const uint8_t *p, size_t n);
#define FNV64_INICIO 1469598103934665603ull

#endif
