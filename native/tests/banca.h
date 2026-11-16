/* Bancada de testes do motor: tun falso, relógio falso, servidores locais e leitura de
 * eventos. O teste faz o papel dos apps do celular. */
#ifndef BANCA_H
#define BANCA_H

#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>

#include "sentinela.h"
#include "sn_transporte.h"

#define BANCA_TETO_MS 5000 /* teto generoso: só estoura se o motor travar */

typedef struct {
    int app_fd; /* lado dos apps no socketpair; o outro lado vai para o motor */
    sn_motor *m;
    pthread_t thread;
    int ret;
    int rodando;
    pthread_mutex_t mu;
    uint64_t agora_us; /* relógio de parede falso */
    uint64_t mono_us;  /* relógio monotônico falso */
    uint8_t eventos[1 << 20];
    size_t n_eventos;
} sn_banca;

/* Preenche os relógios de c com os falsos (parede começa em 1.700.000.000 s). */
int banca_iniciar(sn_banca *b, sn_config *c);
/* Para o motor, espera a thread e chama sn_motor_encerrar (eventos finais ficam legíveis). */
void banca_parar(sn_banca *b);
/* Destrói o motor e fecha o lado dos apps. */
void banca_fim(sn_banca *b);

/* Avança os dois relógios (o tempo passa). */
void banca_avancar(sn_banca *b, uint64_t us);
/* Mexe só no relógio de parede (o Android acertando a hora), para frente ou para trás. */
void banca_ajustar_hora(sn_banca *b, int64_t us);
int banca_enviar(sn_banca *b, const uint8_t *p, size_t n);
/* Espera um pacote vindo do motor até `ms`; devolve o tamanho ou -1 no tempo esgotado. */
ssize_t banca_receber(sn_banca *b, uint8_t *buf, size_t cap, int ms);

/* Drena eventos do motor para b->eventos e procura o primeiro do tipo, a partir do
 * deslocamento *de (atualizado para depois dele). Espera até `ms`. Devolve ponteiro para
 * o corpo e o tamanho em *tam, ou NULL no tempo esgotado. */
const uint8_t *banca_evento(sn_banca *b, uint8_t tipo, size_t *de, uint16_t *tam, int ms);
/* Conta eventos de um tipo já drenados. */
int banca_conta(sn_banca *b, uint8_t tipo);

/* Servidor UDP local de eco (127.0.0.1 ou ::1) numa thread; ou "DNS" falso que responde
 * qualquer consulta com a fixture dns_cname_a, trocando o id. */
typedef struct {
    int fd;
    uint16_t porta;
    int parar;
    int dns;
    pthread_t thread;
} sn_servidor_teste;

int servidor_udp_iniciar(sn_servidor_teste *s, int versao, int dns);
void servidor_udp_parar(sn_servidor_teste *s);

uint32_t le32_ev(const uint8_t *p);
uint64_t le64_ev(const uint8_t *p);
uint16_t le16_ev(const uint8_t *p);

#endif
