/* Leitura de cabeçalhos IPv4 e IPv6. Contrato em include/sn_ip.h.
 *
 * Regra de ouro: o pacote vem de fora e pode mentir. Antes de ler qualquer byte p[k],
 * o código garante que k < n; e todo campo de tamanho é conferido contra o buffer.
 * Campos são lidos byte a byte (nunca com cast para struct), o que evita problemas de
 * alinhamento e de ordem dos bytes.
 *
 * Aulas: 01 (bits e máscaras), 02 (ponteiros e buffers), 04 (cabeçalhos IP).
 */
#include <string.h>

#include "bytes.h"
#include "sn_ip.h"

/* ---------------------------------------------------------------- IPv4 (RFC 791) */

static int ler_v4(const uint8_t *p, size_t n, sn_ip *out) {
    if (n < 20)
        return SN_ERR_CURTO;

    /* IHL: 4 bits de baixo do primeiro byte, em palavras de 4 bytes (5 = 20 bytes). */
    size_t cabecalho = (size_t)(p[0] & 0x0f) * 4;
    if (cabecalho < 20)
        return SN_ERR_CABECALHO;

    size_t total = be16(p + 2); /* Total Length: cabeçalho + dados */
    if (cabecalho > n || total < cabecalho || total > n)
        return SN_ERR_TAMANHO;

    /* Byte 6: 3 bits de flags (o bit 0x20 é "More Fragments") + início do offset de 13 bits. */
    int mais_fragmentos = (p[6] & 0x20) != 0;
    unsigned offset = (unsigned)((p[6] & 0x1f) << 8 | p[7]);
    if (mais_fragmentos || offset != 0)
        return SN_ERR_FRAGMENTO;

    out->versao = 4;
    out->ttl = p[8];
    out->protocolo = p[9];
    out->tam_cabecalho = (uint16_t)cabecalho;
    out->tam_total = (uint16_t)total;
    memcpy(out->origem, p + 12, 4); /* os 12 bytes restantes já foram zerados */
    memcpy(out->destino, p + 16, 4);
    return SN_OK;
}

/* ---------------------------------------------------------------- IPv6 (RFC 8200) */

enum {
    V6_HOP_BY_HOP = 0,
    V6_ROUTING = 43,
    V6_FRAGMENTO = 44,
    V6_DEST_OPTIONS = 60,
    V6_MAX_EXTENSOES = 8,
};

static int ler_v6(const uint8_t *p, size_t n, sn_ip *out) {
    if (n < 40)
        return SN_ERR_CURTO;

    size_t total = 40 + (size_t)be16(p + 4); /* Payload Length não conta os 40 fixos */
    if (total > n)
        return SN_ERR_TAMANHO;

    /* Percorre a corrente de extensões: cada uma diz qual é a próxima ("Next Header").
     * O limite impede que um pacote malicioso nos prenda num laço longo. */
    uint8_t proximo = p[6];
    size_t pos = 40;
    for (int k = 0;; k++) {
        if (proximo == V6_FRAGMENTO)
            return SN_ERR_FRAGMENTO;
        if (proximo != V6_HOP_BY_HOP && proximo != V6_ROUTING && proximo != V6_DEST_OPTIONS)
            break; /* chegou na camada de cima (TCP, UDP, ICMPv6...) */
        if (k == V6_MAX_EXTENSOES)
            return SN_ERR_CABECALHO;
        if (pos + 2 > total) /* precisa ler os 2 primeiros bytes da extensão */
            return SN_ERR_CABECALHO;
        size_t tam = ((size_t)p[pos + 1] + 1) * 8; /* Hdr Ext Len: blocos de 8, sem os 8 iniciais */
        if (pos + tam > total)
            return SN_ERR_CABECALHO;
        proximo = p[pos];
        pos += tam;
    }

    out->versao = 6;
    out->ttl = p[7]; /* Hop Limit */
    out->protocolo = proximo;
    out->tam_cabecalho = (uint16_t)pos;
    out->tam_total = (uint16_t)total;
    memcpy(out->origem, p + 8, 16);
    memcpy(out->destino, p + 24, 16);
    return SN_OK;
}

int sn_ip_ler(const uint8_t *p, size_t n, sn_ip *out) {
    memset(out, 0, sizeof *out);
    if (n < 1)
        return SN_ERR_CURTO;
    switch (p[0] >> 4) { /* versão: 4 bits de cima do primeiro byte */
    case 4:
        return ler_v4(p, n, out);
    case 6:
        return ler_v6(p, n, out);
    default:
        return SN_ERR_VERSAO;
    }
}
