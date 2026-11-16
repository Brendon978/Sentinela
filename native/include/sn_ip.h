/* Sentinela — leitura de cabeçalhos IP (Tarefa 1).
 *
 * Contrato que o Brendon implementa em src/checksum.c e src/ip.c.
 * Referências: RFC 791 §3.1 (IPv4), RFC 8200 §3–4 (IPv6), RFC 1071 (checksum).
 */
#ifndef SN_IP_H
#define SN_IP_H

#include <stddef.h>
#include <stdint.h>

/* Códigos de retorno. Erros são sempre negativos. */
enum {
    SN_OK = 0,
    SN_ERR_CURTO = -1,      /* buffer menor que o cabeçalho mínimo */
    SN_ERR_VERSAO = -2,     /* versão diferente de 4 e 6 */
    SN_ERR_CABECALHO = -3,  /* cabeçalho incoerente: IHL < 5, extensões demais ou cortadas */
    SN_ERR_TAMANHO = -4,    /* tamanho total declarado maior que o buffer, ou menor que o cabeçalho */
    SN_ERR_FRAGMENTO = -5,  /* pacote fragmentado (IPv4 com MF ou offset, IPv6 com extensão 44) */
};

/* Resultado da leitura de um pacote IP. */
typedef struct {
    uint8_t versao;         /* 4 ou 6 */
    uint8_t protocolo;      /* protocolo da camada de cima, já depois das extensões IPv6 (6 = TCP, 17 = UDP) */
    uint8_t ttl;            /* TTL (IPv4) ou Hop Limit (IPv6) */
    uint16_t tam_cabecalho; /* bytes do início do pacote até a camada de cima (IPv6: 40 + extensões) */
    uint16_t tam_total;     /* tamanho do pacote IP segundo o cabeçalho (IPv6: 40 + Payload Length) */
    uint8_t origem[16];     /* endereço de origem; IPv4 ocupa os 4 primeiros bytes e o resto fica zero */
    uint8_t destino[16];    /* endereço de destino, mesma regra */
} sn_ip;

/* Soma de verificação da Internet (RFC 1071) sobre n bytes, começando de soma_inicial.
 *
 * - soma_inicial é uma soma parcial ainda não dobrada nem complementada (0 para começar);
 *   serve para a Tarefa 2 somar o pseudo-cabeçalho antes.
 * - n pode ser ímpar: o último byte conta como se viesse seguido de um byte zero.
 * - Devolve o checksum final (dobrado e complementado) como número: escrito em big-endian
 *   no campo do cabeçalho, fica correto. Sobre um cabeçalho que já tem o checksum certo,
 *   o resultado é 0.
 */
uint16_t sn_checksum(const uint8_t *p, size_t n, uint32_t soma_inicial);

/* Lê o cabeçalho IP no início de p (n bytes) e preenche *out.
 *
 * - Nunca lê fora de p[0..n-1], qualquer que seja o conteúdo.
 * - Buffer maior que tam_total é aceito (sobra é ignorada).
 * - IPv6: pula Hop-by-Hop (0), Routing (43) e Destination Options (60), no máximo 8 extensões.
 * - Não confere o checksum do IPv4 (o kernel já entrega pacotes válidos no tun).
 * - Devolve SN_OK ou um erro negativo; em erro, *out pode ficar parcialmente preenchido.
 */
int sn_ip_ler(const uint8_t *p, size_t n, sn_ip *out);

#endif
