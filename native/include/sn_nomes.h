/* Sentinela — nomes vistos no tráfego: respostas DNS e SNI do TLS (Tarefa 4).
 *
 * Os dois parsers recebem dado vindo da rede, potencialmente hostil: nunca leem fora do
 * buffer, limitam laços e tamanhos, e só escrevem no destino dentro de `cap`.
 * Referências: RFC 1035 §4.1 (DNS) e §4.1.4 (compressão); RFC 8446 §4.1.2 e RFC 6066 §3 (SNI).
 */
#ifndef SN_NOMES_H
#define SN_NOMES_H

#include <stddef.h>
#include <stdint.h>

#include "sn_ip.h"

enum {
    SN_ERR_FORMATO = -6,  /* não é o que se esperava (não é resposta DNS, não é ClientHello, sem SNI) */
    SN_NOME_MAX = 253,    /* maior nome DNS em texto */
    SN_DNS_MAX_ENDERECOS = 16,
};

typedef struct {
    uint8_t versao; /* 4 ou 6 */
    uint8_t ip[16]; /* IPv4 nos 4 primeiros bytes */
} sn_endereco;

typedef struct {
    uint16_t id;
    char nome[SN_NOME_MAX + 1]; /* nome perguntado, em minúsculas, terminado em '\0' */
    int n_enderecos;            /* A e AAAA das respostas (até SN_DNS_MAX_ENDERECOS; o resto é ignorado) */
    sn_endereco enderecos[SN_DNS_MAX_ENDERECOS];
} sn_dns_resposta;

/* Lê uma resposta DNS (payload UDP). Devolve SN_OK, SN_ERR_FORMATO se for consulta ou
 * não tiver pergunta, ou outro erro negativo se estiver malformada. Os endereços vêm de
 * todos os registros A/AAAA da seção de respostas (inclusive depois de CNAME). */
int sn_dns_ler_resposta(const uint8_t *p, size_t n, sn_dns_resposta *out);

/* Procura o SNI no começo do fluxo TCP do cliente (p = primeiros n bytes que o app
 * enviou). O ClientHello pode chegar em mais de um segmento, então:
 *   SN_OK          achou; `nome` recebe o SNI em minúsculas, terminado em '\0'
 *   SN_ERR_CURTO   ainda faltam bytes: chame de novo com mais dados
 *   SN_ERR_FORMATO não é TLS ClientHello, ou não tem SNI: não adianta tentar de novo
 *   SN_ERR_TAMANHO o nome não cabe em `cap` (incluindo o '\0')
 */
int sn_tls_sni(const uint8_t *p, size_t n, char *nome, size_t cap);

#endif
