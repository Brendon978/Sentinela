/* Soma de verificação da Internet (RFC 1071). Contrato em include/sn_ip.h.
 *
 * Usada nos cabeçalhos IPv4, UDP, TCP e ICMP. A ideia: somar o pacote em palavras de
 * 16 bits com "complemento de um" (o vai-um que passa de 16 bits volta somado embaixo)
 * e inverter os bits no fim. Quem recebe soma tudo de novo, incluindo o campo do
 * checksum; se nada mudou no caminho, o resultado é 0.
 *
 * Aula: docs/estudo/aulas/01-bits-e-bytes.md (seções 4 e 5).
 */
#include "sn_ip.h"

uint16_t sn_checksum(const uint8_t *p, size_t n, uint32_t soma_inicial) {
    /* 32 bits de acumulador: sobra espaço para o vai-um de muitas somas de 16 bits.
     * soma_inicial permite encadear (a Tarefa 2 soma o pseudo-cabeçalho antes). */
    uint32_t soma = soma_inicial;

    /* Cada par de bytes vira um número de 16 bits em big-endian (ordem da rede):
     * bytes 0x45 0x00 -> 0x4500. "i + 1 < n" garante que o par inteiro existe. */
    size_t i = 0;
    for (; i + 1 < n; i += 2)
        soma += (uint32_t)((p[i] << 8) | p[i + 1]);

    /* Tamanho ímpar: o último byte entra como parte alta, com zero embaixo (0xAB -> 0xAB00). */
    if (i < n)
        soma += (uint32_t)p[i] << 8;

    /* Dobra: o que passou de 16 bits volta somado embaixo. Pode gerar outro vai-um,
     * por isso é um while e não um if. */
    while (soma >> 16)
        soma = (soma & 0xffffu) + (soma >> 16);

    /* Complemento de um: inverte os bits. O cast descarta a metade de cima (já zerada). */
    return (uint16_t)~soma;
}
