/* Partes internas do motor, compartilhadas por motor.c, eventos.c, relay_udp.c e
 * relay_tcp.c. Não faz parte da API pública (essa é include/sentinela.h). */
#ifndef SN_MOTOR_INTERNO_H
#define SN_MOTOR_INTERNO_H

#include <pthread.h>

#include "sentinela.h"
#include "sn_fluxos.h"
#include "sn_pcap.h"

/* ---------------------------------------------------------------- fila de eventos */

#define SN_FILA_MAX (4u << 20) /* 4 MiB: acima disso, descarta e avisa com SN_EV_PERDA */

typedef struct {
    pthread_mutex_t mu;
    uint8_t *buf;
    size_t n, cap;
    uint32_t perdidos;
} sn_fila;

int sn_fila_iniciar(sn_fila *f);
void sn_fila_liberar(sn_fila *f);
void sn_fila_por(sn_fila *f, uint8_t tipo, const uint8_t *corpo, uint16_t n);
size_t sn_fila_tirar(sn_fila *f, uint8_t *dst, size_t cap);

/* ---------------------------------------------------------------- estado por fluxo */

/* Início comum do estado de cada relé (fluxo->estado aponta para um destes). */
typedef struct sn_estado {
    int fd;         /* socket real do fluxo; -1 se fechado */
    short eventos;  /* o que pedir ao poll: POLLIN, POLLOUT */
    int alterado;   /* bytes mudaram desde o último SN_EV_FLUXO_BYTES */
    void (*liberar_extra)(struct sn_estado *e); /* buffers do relé; NULL se não tiver */
} sn_estado;

/* ---------------------------------------------------------------- o motor */

struct sn_motor {
    sn_config c;
    pthread_mutex_t mu_dns; /* protege c.dns_real/c.n_dns_real (sn_motor_trocar_dns vem de outra thread) */
    sn_pcap *pcap;
    sn_fluxos *fluxos;
    sn_fila fila;
    int fd_tun;
    int fd_parar;          /* eventfd: sn_motor_parar escreve, o laço acorda */
    int encerrado;
    uint64_t ultimo_tique; /* última passada de expiração/bytes */
    uint8_t rx[65536];     /* buffer de leitura (tun e sockets) */
    uint8_t tx[65536 + 128];
};

/* Dois relógios: `parede` (1970, UTC) para carimbos e eventos; `mono` para prazos. */
typedef struct {
    uint64_t parede;
    uint64_t mono;
} sn_tempo;

sn_tempo sn_agora(const sn_motor *m);

/* Escreve no tun um pacote para os apps e, se a escrita deu certo, grava no pcap.
 * Devolve 0, ou -1 se o pacote não entrou no tun (fica fora do pcap e das contas). */
int sn_escrever_tun(sn_motor *m, const uint8_t *p, size_t n, sn_tempo agora);

/* Eventos (formato C2 em sentinela.h). */
void sn_ev_fluxo_novo(sn_motor *m, const sn_fluxo *f);
void sn_ev_bytes(sn_motor *m, const sn_fluxo *f);
void sn_ev_fim(sn_motor *m, const sn_fluxo *f, uint64_t fim_us, uint8_t motivo);
void sn_ev_dns(sn_motor *m, const sn_dns_resposta *r);
void sn_ev_sni(sn_motor *m, const sn_fluxo *f, const char *nome, int ech);

/* Soquete não bloqueante conectado a um servidor. -1 em erro. `tipo` = SOCK_DGRAM ou SOCK_STREAM.
 * Para TCP, o connect fica em andamento (EINPROGRESS) e termina quando o socket fica gravável. */
int sn_socket_para(const sn_endereco *e, uint16_t porta, int tipo);

/* Relés. Regra de vida: os relés NUNCA liberam o fluxo; marcam f->fechado e fecham o
 * socket (fd = -1). Quem libera é sn_fluxos_expirar, no começo de cada volta do laço,
 * chamando sn_relay_liberar. Assim nenhum ponteiro guardado na volta atual fica inválido. */
void sn_udp_do_app(sn_motor *m, const sn_ip *ip, const uint8_t *pkt, sn_tempo agora);
void sn_udp_socket(sn_motor *m, sn_fluxo *f, short revents, sn_tempo agora);
void sn_tcp_do_app(sn_motor *m, const sn_ip *ip, const uint8_t *pkt, sn_tempo agora);
void sn_tcp_socket(sn_motor *m, sn_fluxo *f, short revents, sn_tempo agora);
/* Chamada a cada tique (1 s) para cada fluxo TCP: retransmissão por tempo. */
void sn_tcp_tique(sn_motor *m, sn_fluxo *f, sn_tempo agora);

enum { SN_PORTA_DNS = 53 };

/* Para onde o fluxo `k` vai de verdade: o próprio destino, ou o DNS real quando o app fala
 * com o DNS virtual na porta 53 (UDP ou TCP). -1 se é o DNS virtual e não há DNS real. */
int sn_destino_real(sn_motor *m, const sn_tupla *k, sn_endereco *dst, uint16_t *porta);

/* Acrescenta k bytes de d ao buffer (buf, n, cap), dobrando a capacidade até `max`.
 * -1 se passaria de `max` ou faltou memória (o buffer fica como estava). */
int sn_anexa(uint8_t **buf, size_t *n, size_t *cap, const uint8_t *d, size_t k, size_t max);

/* Insere um fluxo novo com os dois relógios certos. NULL sem memória. */
sn_fluxo *sn_novo_fluxo(sn_motor *m, const sn_tupla *k, sn_tempo agora);
void sn_relay_liberar(sn_fluxo *f); /* fecha o socket e libera f->estado */

#endif
