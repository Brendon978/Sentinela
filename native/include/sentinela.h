/* Sentinela — API pública do motor de captura (contrato C1 do plano, Tarefas 6–8).
 *
 * Uso (uma thread roda o motor; outra lê eventos e manda parar):
 *   sn_motor *m = sn_motor_criar(&config);
 *   thread A: sn_motor_rodar(m, fd_tun);          // bloqueia até sn_motor_parar
 *   thread B: sn_motor_eventos(m, buf, cap) a cada 250 ms; sn_motor_parar(m) para encerrar
 *   depois que rodar voltou: sn_motor_destruir(m);
 */
#ifndef SENTINELA_H
#define SENTINELA_H

#include <stddef.h>
#include <stdint.h>

#include "sn_nomes.h"

const char *sn_versao(void);

/* Tipos de evento (contrato C2): registros `u8 tipo | u16 tamanho | corpo`, little-endian. */
enum {
    SN_EV_FLUXO_NOVO = 1,  /* u32 id, u8 versao, u8 proto, u8[16] ip_orig, u16 porta_orig, u8[16] ip_dest, u16 porta_dest, u64 inicio_us */
    SN_EV_FLUXO_BYTES = 2, /* u32 id, u64 bytes_env, u64 bytes_rec, u32 pacotes (totais) */
    SN_EV_FLUXO_FIM = 3,   /* u32 id, u64 fim_us, u8 motivo (SN_FIM_*) */
    SN_EV_DNS = 4,         /* u16 n, u8 versao[n], u8[16] ip[n], u16 tam_nome, nome */
    SN_EV_SNI = 5,         /* u32 id, u16 tam_nome, nome */
    SN_EV_PERDA = 6,       /* u32 eventos_descartados */
};

#define SN_MAX_DNS_REAIS 4

typedef struct {
    sn_endereco endereco;
    uint16_t porta; /* 53 normalmente; os testes usam outra */
} sn_servidor;

typedef struct {
    const char *caminho_pcap;  /* NULL = não grava */
    /* Endereços de DNS que o tun anuncia aos apps (ex.: 10.111.0.53 e fd00:5e:1::53).
     * Consulta UDP 53 para eles é repassada ao primeiro DNS real. */
    sn_endereco dns_virtual[2];
    int n_dns_virtual;
    sn_servidor dns_real[SN_MAX_DNS_REAIS];
    int n_dns_real;
    int forcar_tcp;            /* 1 = descarta UDP 443 (QUIC), para os apps caírem em TCP */
    /* Relógio de parede em microssegundos desde 1970 (UTC), para os carimbos do pcap e dos
     * eventos. NULL = relógio do sistema. */
    uint64_t (*relogio_us)(void *ctx);
    /* Relógio monotônico em microssegundos (nunca volta; não acompanha ajustes de hora),
     * para prazos e expiração. NULL = CLOCK_MONOTONIC. Os dois recebem relogio_ctx. */
    uint64_t (*relogio_mono_us)(void *ctx);
    void *relogio_ctx;
} sn_config;

typedef struct sn_motor sn_motor;

/* Copia a configuração. NULL se faltar memória ou o pcap não abrir. */
sn_motor *sn_motor_criar(const sn_config *c);

/* Roda o laço até sn_motor_parar. O motor passa a ser dono de fd_tun (fecha no destruir).
 * Devolve 0 ao parar normalmente, -1 se o tun deu erro fatal ou foi fechado do outro lado. */
int sn_motor_rodar(sn_motor *m, int fd_tun);

/* Pode ser chamada de qualquer thread, a qualquer momento (inclusive antes de rodar). */
void sn_motor_parar(sn_motor *m);

/* Troca os DNS reais (a rede mudou, ex.: Wi-Fi -> dados). Qualquer thread. Vale para os
 * fluxos de DNS novos; os já abertos seguem até expirar. n acima de SN_MAX_DNS_REAIS é cortado. */
void sn_motor_trocar_dns(sn_motor *m, const sn_servidor *dns, int n);

/* Drena a fila de eventos para buf (só registros inteiros). Devolve quantos bytes escreveu.
 * Pode ser chamada de qualquer thread. Se a fila passou de 4 MiB, eventos foram
 * descartados e o primeiro registro entregue depois disso é SN_EV_PERDA. */
size_t sn_motor_eventos(sn_motor *m, uint8_t *buf, size_t cap);

/* Só depois que sn_motor_rodar voltou (ou se nunca rodou). Emite SN_EV_FLUXO_FIM dos
 * fluxos abertos, fecha sockets, o pcap e o tun. Os eventos finais continuam disponíveis
 * em sn_motor_eventos até a destruição; leia antes, se precisar deles. */
void sn_motor_destruir(sn_motor *m);

/* Encerra o que estiver aberto e emite os eventos finais, sem liberar o motor. Depois
 * dela, sn_motor_eventos entrega o resto e sn_motor_destruir só libera. */
void sn_motor_encerrar(sn_motor *m);

#endif
