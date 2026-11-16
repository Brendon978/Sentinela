/* Ler e escrever inteiros byte a byte (aula 01, seção 7: ordem dos bytes).
 *
 *   be16/be32       lê big-endian (ordem da rede: cabeçalhos IP, TCP, UDP, DNS, TLS)
 *   le32            lê little-endian (arquivo pcap)
 *   put_be16/32     escreve big-endian
 *   put_le16/32/64  escreve little-endian (pcap e eventos para o Kotlin)
 *
 * Montar byte a byte evita cast para ponteiro de inteiro (alinhamento e strict aliasing) e
 * dá o mesmo resultado em qualquer processador. */
#ifndef SN_BYTES_H
#define SN_BYTES_H

#include <stdint.h>

static inline uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

static inline uint32_t be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static inline uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static inline void put_be16(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void put_be32(uint8_t *p, uint32_t v) {
    put_be16(p, v >> 16);
    put_be16(p + 2, v);
}

static inline void put_le16(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static inline void put_le32(uint8_t *p, uint32_t v) {
    put_le16(p, v);
    put_le16(p + 2, v >> 16);
}

static inline void put_le64(uint8_t *p, uint64_t v) {
    put_le32(p, (uint32_t)v);
    put_le32(p + 4, (uint32_t)(v >> 32));
}

#endif
