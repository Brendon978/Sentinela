/* UDP e TCP: leitura, checksum com pseudo-cabeçalho e montagem de pacotes.
 * Contrato em include/sn_transporte.h. Aulas 04 (seção 7) e 05 (seção 7).
 */
#include <string.h>

#include "bytes.h"
#include "sn_transporte.h"

sn_tupla sn_tupla_de(const sn_ip *ip, uint8_t protocolo, uint16_t porta_origem, uint16_t porta_destino) {
    sn_tupla t = {.versao = ip->versao, .protocolo = protocolo, .porta_origem = porta_origem,
                  .porta_destino = porta_destino};
    memcpy(t.ip_origem, ip->origem, 16);
    memcpy(t.ip_destino, ip->destino, 16);
    return t;
}

int sn_tupla_igual(const sn_tupla *a, const sn_tupla *b) {
    return a->versao == b->versao && a->protocolo == b->protocolo && a->porta_origem == b->porta_origem &&
           a->porta_destino == b->porta_destino && memcmp(a->ip_origem, b->ip_origem, 16) == 0 &&
           memcmp(a->ip_destino, b->ip_destino, 16) == 0;
}

sn_tupla sn_tupla_inversa(const sn_tupla *t) {
    sn_tupla v = *t;
    memcpy(v.ip_origem, t->ip_destino, 16);
    memcpy(v.ip_destino, t->ip_origem, 16);
    v.porta_origem = t->porta_destino;
    v.porta_destino = t->porta_origem;
    return v;
}

/* ---------------------------------------------------------------- leitura */

int sn_udp_ler(const uint8_t *p, size_t n, sn_udp *out) {
    if (n < 8)
        return SN_ERR_CURTO;
    out->porta_origem = be16(p);
    out->porta_destino = be16(p + 2);
    out->tamanho = be16(p + 4);
    if (out->tamanho < 8 || out->tamanho > n)
        return SN_ERR_TAMANHO;
    return SN_OK;
}

int sn_tcp_ler(const uint8_t *p, size_t n, sn_tcp *out) {
    if (n < 20)
        return SN_ERR_CURTO;
    size_t cabecalho = (size_t)(p[12] >> 4) * 4; /* Data Offset: 4 bits de cima, em palavras de 4 bytes */
    if (cabecalho < 20)
        return SN_ERR_CABECALHO;
    if (cabecalho > n)
        return SN_ERR_TAMANHO;

    out->porta_origem = be16(p);
    out->porta_destino = be16(p + 2);
    out->seq = be32(p + 4);
    out->ack = be32(p + 8);
    out->flags = p[13] & 0x3f; /* só as 6 flags clássicas */
    out->janela = be16(p + 14);
    out->tam_cabecalho = (uint16_t)cabecalho;
    out->mss = 0;

    /* Opções: lista de (tipo, tamanho, valor). Tipo 0 = fim, 1 = NOP (1 byte só).
     * Opção malformada encerra a leitura das opções sem invalidar o segmento. */
    size_t i = 20;
    while (i < cabecalho) {
        uint8_t tipo = p[i];
        if (tipo == 0)
            break;
        if (tipo == 1) {
            i++;
            continue;
        }
        if (i + 1 >= cabecalho)
            break;
        size_t tam = p[i + 1];
        if (tam < 2 || i + tam > cabecalho)
            break;
        if (tipo == 2 && tam == 4)
            out->mss = be16(p + i + 2);
        i += tam;
    }
    return SN_OK;
}

/* ---------------------------------------------------------------- checksum */

uint32_t sn_soma_pseudo(uint8_t versao, const uint8_t *origem, const uint8_t *destino,
                        uint8_t protocolo, uint32_t tam_transporte) {
    /* O pseudo-cabeçalho não viaja no pacote: é somado só para o checksum "amarrar" o
     * segmento aos endereços. IPv4: ips (4+4), zero, protocolo, tamanho (16 bits).
     * IPv6: ips (16+16), tamanho (32 bits), zeros, next header. A soma é a mesma ideia. */
    size_t tam_ip = versao == 4 ? 4 : 16;
    uint32_t soma = 0;
    for (size_t i = 0; i < tam_ip; i += 2) {
        soma += (uint32_t)((origem[i] << 8) | origem[i + 1]);
        soma += (uint32_t)((destino[i] << 8) | destino[i + 1]);
    }
    soma += protocolo;
    soma += tam_transporte >> 16;
    soma += tam_transporte & 0xffff;
    return soma;
}

int sn_transporte_checksum_ok(const uint8_t *pacote, const sn_ip *ip) {
    const uint8_t *l4 = pacote + ip->tam_cabecalho;
    uint32_t n = (uint32_t)(ip->tam_total - ip->tam_cabecalho);
    if (ip->protocolo == SN_PROTO_UDP) {
        if (n < 8)
            return 0;
        if (ip->versao == 4 && l4[6] == 0 && l4[7] == 0)
            return 1; /* IPv4 permite UDP sem checksum */
        n = be16(l4 + 4) <= n ? be16(l4 + 4) : n;
    } else if (ip->protocolo != SN_PROTO_TCP) {
        return 0;
    }
    uint32_t pseudo = sn_soma_pseudo(ip->versao, ip->origem, ip->destino, ip->protocolo, n);
    return sn_checksum(l4, n, pseudo) == 0;
}

/* ---------------------------------------------------------------- montagem */

/* Escreve o cabeçalho IP para `tam_l4` bytes de transporte; devolve o tamanho do
 * cabeçalho (20 ou 40), ou 0 se não couber. */
static size_t montar_ip(uint8_t *buf, size_t cap, const sn_tupla *t, size_t tam_l4) {
    if (t->versao == 4) {
        if (cap < 20 + tam_l4 || 20 + tam_l4 > 0xffff)
            return 0;
        memset(buf, 0, 20);
        buf[0] = 0x45;                            /* versão 4, IHL 5 */
        put_be16(buf + 2, (uint32_t)(20 + tam_l4));
        buf[6] = 0x40;                            /* DF: não fragmentar */
        buf[8] = 64;                              /* TTL */
        buf[9] = t->protocolo;
        memcpy(buf + 12, t->ip_origem, 4);
        memcpy(buf + 16, t->ip_destino, 4);
        put_be16(buf + 10, sn_checksum(buf, 20, 0));
        return 20;
    }
    if (cap < 40 + tam_l4 || tam_l4 > 0xffff)
        return 0;
    memset(buf, 0, 40);
    buf[0] = 0x60;                                /* versão 6 */
    put_be16(buf + 4, (uint32_t)tam_l4);         /* Payload Length */
    buf[6] = t->protocolo;                        /* Next Header */
    buf[7] = 64;                                  /* Hop Limit */
    memcpy(buf + 8, t->ip_origem, 16);
    memcpy(buf + 24, t->ip_destino, 16);
    return 40;
}

static void fecha_checksum(uint8_t *l4, size_t tam_l4, size_t pos_checksum, const sn_tupla *t) {
    uint32_t pseudo = sn_soma_pseudo(t->versao, t->ip_origem, t->ip_destino, t->protocolo,
                                     (uint32_t)tam_l4);
    uint16_t c = sn_checksum(l4, tam_l4, pseudo);
    if (t->protocolo == SN_PROTO_UDP && c == 0)
        c = 0xffff; /* no UDP, 0 significa "sem checksum"; o equivalente é 0xFFFF */
    put_be16(l4 + pos_checksum, c);
}

size_t sn_montar_udp(uint8_t *buf, size_t cap, const sn_tupla *t, const uint8_t *dados, size_t n) {
    sn_tupla u = *t;
    u.protocolo = SN_PROTO_UDP;
    size_t tam_l4 = 8 + n;
    size_t h = montar_ip(buf, cap, &u, tam_l4);
    if (h == 0)
        return 0;
    uint8_t *l4 = buf + h;
    put_be16(l4, u.porta_origem);
    put_be16(l4 + 2, u.porta_destino);
    put_be16(l4 + 4, (uint32_t)tam_l4);
    l4[6] = l4[7] = 0;
    if (n)
        memcpy(l4 + 8, dados, n);
    fecha_checksum(l4, tam_l4, 6, &u);
    return h + tam_l4;
}

size_t sn_montar_tcp(uint8_t *buf, size_t cap, const sn_tupla *t, uint32_t seq, uint32_t ack,
                     uint8_t flags, uint16_t janela, uint16_t mss, const uint8_t *dados, size_t n) {
    sn_tupla u = *t;
    u.protocolo = SN_PROTO_TCP;
    size_t cabecalho = mss ? 24 : 20;
    size_t tam_l4 = cabecalho + n;
    size_t h = montar_ip(buf, cap, &u, tam_l4);
    if (h == 0)
        return 0;
    uint8_t *l4 = buf + h;
    memset(l4, 0, cabecalho);
    put_be16(l4, u.porta_origem);
    put_be16(l4 + 2, u.porta_destino);
    put_be32(l4 + 4, seq);
    put_be32(l4 + 8, ack);
    l4[12] = (uint8_t)((cabecalho / 4) << 4); /* Data Offset */
    l4[13] = flags;
    put_be16(l4 + 14, janela);
    if (mss) {
        l4[20] = 2; /* opção MSS */
        l4[21] = 4;
        put_be16(l4 + 22, mss);
    }
    if (n)
        memcpy(l4 + cabecalho, dados, n);
    fecha_checksum(l4, tam_l4, 16, &u);
    return h + tam_l4;
}
