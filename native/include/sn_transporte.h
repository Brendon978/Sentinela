/* Sentinela — UDP, TCP e montagem de pacotes (Tarefa 2).
 * Referências: RFC 768 (UDP), RFC 9293 (TCP), RFC 8200 §8.1 (pseudo-cabeçalho IPv6).
 */
#ifndef SN_TRANSPORTE_H
#define SN_TRANSPORTE_H

#include <stddef.h>
#include <stdint.h>

#include "sn_ip.h"

enum { SN_PROTO_TCP = 6, SN_PROTO_UDP = 17 };

/* Flags do TCP (byte 13 do cabeçalho). */
enum {
    SN_TCP_FIN = 0x01,
    SN_TCP_SYN = 0x02,
    SN_TCP_RST = 0x04,
    SN_TCP_PSH = 0x08,
    SN_TCP_ACK = 0x10,
};

/* Os dois lados de um fluxo. IPv4 ocupa os 4 primeiros bytes dos endereços (resto zero). */
typedef struct {
    uint8_t versao;    /* 4 ou 6 */
    uint8_t protocolo; /* SN_PROTO_TCP ou SN_PROTO_UDP */
    uint8_t ip_origem[16];
    uint8_t ip_destino[16];
    uint16_t porta_origem;
    uint16_t porta_destino;
} sn_tupla;

typedef struct {
    uint16_t porta_origem;
    uint16_t porta_destino;
    uint16_t tamanho; /* cabeçalho (8) + dados, como declarado no campo Length */
} sn_udp;

typedef struct {
    uint16_t porta_origem;
    uint16_t porta_destino;
    uint32_t seq;
    uint32_t ack;
    uint8_t flags;          /* SN_TCP_* */
    uint16_t janela;        /* valor bruto do campo Window */
    uint16_t tam_cabecalho; /* Data Offset × 4 (20 a 60) */
    uint16_t mss;           /* opção MSS (tipo 2); 0 se ausente */
} sn_tcp;

/* Tupla a partir do cabeçalho IP já lido e das portas. */
sn_tupla sn_tupla_de(const sn_ip *ip, uint8_t protocolo, uint16_t porta_origem, uint16_t porta_destino);

/* A mesma conversa no sentido contrário (origem e destino trocados): o endereçamento das
 * respostas que o motor escreve para o app. */
sn_tupla sn_tupla_inversa(const sn_tupla *t);

/* 1 se as duas tuplas são iguais campo a campo (sem comparar bytes de enchimento). */
int sn_tupla_igual(const sn_tupla *a, const sn_tupla *b);

/* Leem o cabeçalho de transporte em p (n = bytes da camada de transporte em diante,
 * isto é, ip.tam_total - ip.tam_cabecalho). Nunca leem fora de p[0..n-1].
 * Devolvem SN_OK ou erro negativo de sn_ip.h. */
int sn_udp_ler(const uint8_t *p, size_t n, sn_udp *out);
int sn_tcp_ler(const uint8_t *p, size_t n, sn_tcp *out);

/* Soma parcial do pseudo-cabeçalho (endereços, protocolo e tamanho da camada de
 * transporte), para passar como soma_inicial de sn_checksum. */
uint32_t sn_soma_pseudo(uint8_t versao, const uint8_t *origem, const uint8_t *destino,
                        uint8_t protocolo, uint32_t tam_transporte);

/* 1 se o checksum UDP/TCP do pacote IP inteiro (já lido em *ip) confere, 0 se não.
 * UDP sobre IPv4 com checksum 0 ("não calculado") conta como válido. */
int sn_transporte_checksum_ok(const uint8_t *pacote, const sn_ip *ip);

/* Montam um pacote IP completo em buf, com todos os checksums, a partir da tupla
 * (origem e destino do pacote que vai ser escrito). Campos fixos: IPv4 com id 0, DF e
 * TTL 64; IPv6 com hop limit 64. Devolvem o tamanho escrito, ou 0 se não couber em cap
 * ou se o pacote passaria de 65535 bytes. */
size_t sn_montar_udp(uint8_t *buf, size_t cap, const sn_tupla *t, const uint8_t *dados, size_t n);

/* mss != 0 acrescenta a opção MSS (4 bytes), usada só no SYN-ACK. */
size_t sn_montar_tcp(uint8_t *buf, size_t cap, const sn_tupla *t, uint32_t seq, uint32_t ack,
                     uint8_t flags, uint16_t janela, uint16_t mss, const uint8_t *dados, size_t n);

#endif
