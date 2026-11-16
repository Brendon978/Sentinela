/* Tarefa 1 — escrita pelo Brendon. Contrato em include/sn_ip.h.
 * Testes: tools/testes-c.sh ip_checksum   (ou Ctrl+Shift+B no VS Code)
 * Meta: os 6 testes ip_checksum_* passando.
 */
#include "sn_ip.h"

uint16_t sn_checksum(const uint8_t *p, size_t n, uint32_t soma_inicial) {
    /* PASSO 1 — crie o acumulador de 32 bits começando em soma_inicial.
     *   Dica: uint32_t soma = ...;
     */
     uint32_t soma = soma_inicial;


    /* PASSO 2 — some os bytes de 2 em 2, cada par vira um número de 16 bits
     * com o primeiro byte na parte alta: bytes 0x45 0x00 -> 0x4500.
     *   Dica: for (size_t i = 0; i + 1 < n; i += 2)  e  (p[i] << 8) | p[i + 1]
     *   O "i + 1 < n" garante que o par inteiro existe.
     */

     for (size_t i=0; i + 1 < n; i += 2)
     {
        soma += (uint32_t)((p[i] << 8) | p[i + 1]);
     }


    /* PASSO 3 — se n for ímpar, sobrou o último byte: ele entra sozinho como
     * parte alta, com zero embaixo (0xAB -> 0xAB00).
     *   Dica: (uint32_t)p[n - 1] << 8   (o cast evita aviso do -Wconversion)
     */


    /* PASSO 4 — "dobre" o que passou de 16 bits de volta para baixo, repetindo
     * enquanto sobrar algo acima dos 16 bits.
     *   Dica: soma = (soma & 0xffff) + (soma >> 16);   dentro de um while
     */


    /* PASSO 5 — inverta os bits e devolva como uint16_t.
     *   Dica: return (uint16_t)~soma;
     *   Quando escrever o seu return, apague as 4 linhas abaixo.
     */
    (void)p;
    (void)n;
    (void)soma_inicial;
    return 0xdead;
}
