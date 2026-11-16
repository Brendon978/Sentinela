/* Gravar e ler .pcap (formato clássico, Raw IP). Contrato em include/sn_pcap.h.
 * Aulas 06 (seção 3, formato pcap) e 08 (integridade da evidência).
 *
 * Os campos do arquivo são escritos byte a byte em little-endian, então o resultado é o
 * mesmo em qualquer máquina, e a leitura não depende de cast para struct.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bytes.h"
#include "sn_pcap.h"

enum {
    PCAP_MAGIC = 0xa1b2c3d4u,
    PCAP_SNAPLEN = 65535,
    PCAP_LINKTYPE_RAW = 101,
    DESCARGA_PACOTES = 256,
    DESCARGA_US = 1000000,
};

struct sn_pcap {
    FILE *f;
    int erro;                 /* alguma escrita falhou */
    unsigned desde_descarga;  /* pacotes desde o último fflush */
    uint64_t ultima_descarga; /* carimbo (us) do último fflush */
};

sn_pcap *sn_pcap_abrir(const char *caminho) {
    sn_pcap *pc = calloc(1, sizeof *pc);
    if (!pc)
        return NULL;
    pc->f = fopen(caminho, "wb");
    if (!pc->f) {
        free(pc);
        return NULL;
    }
    uint8_t h[24] = {0};
    put_le32(h, PCAP_MAGIC);
    h[4] = 2; /* versão 2.4 (dois campos de 16 bits) */
    h[6] = 4;
    /* bytes 8-15: fuso e precisão, sempre 0 */
    put_le32(h + 16, PCAP_SNAPLEN);
    put_le32(h + 20, PCAP_LINKTYPE_RAW);
    if (fwrite(h, 1, sizeof h, pc->f) != sizeof h)
        pc->erro = 1;
    return pc;
}

int sn_pcap_gravar(sn_pcap *pc, uint64_t quando_us, const uint8_t *p, size_t n) {
    size_t gravado = n > PCAP_SNAPLEN ? PCAP_SNAPLEN : n;
    uint8_t r[16];
    put_le32(r, (uint32_t)(quando_us / 1000000));
    put_le32(r + 4, (uint32_t)(quando_us % 1000000));
    put_le32(r + 8, (uint32_t)gravado);
    put_le32(r + 12, n > UINT32_MAX ? UINT32_MAX : (uint32_t)n);
    if (fwrite(r, 1, sizeof r, pc->f) != sizeof r || fwrite(p, 1, gravado, pc->f) != gravado)
        pc->erro = 1;

    /* Descarga periódica: se o app morrer, perde-se no máximo ~1 s de pacotes. */
    pc->desde_descarga++;
    if (pc->desde_descarga >= DESCARGA_PACOTES || quando_us - pc->ultima_descarga >= DESCARGA_US) {
        if (fflush(pc->f) != 0)
            pc->erro = 1;
        pc->desde_descarga = 0;
        pc->ultima_descarga = quando_us;
    }
    return pc->erro ? -1 : 0;
}

int sn_pcap_fechar(sn_pcap *pc) {
    if (!pc)
        return 0;
    int erro = pc->erro;
    if (fclose(pc->f) != 0) /* fclose também descarrega */
        erro = 1;
    free(pc);
    return erro ? -1 : 0;
}

long sn_pcap_ler(const char *caminho, sn_pcap_visita fn, void *ctx) {
    FILE *f = fopen(caminho, "rb");
    if (!f)
        return -1;
    uint8_t h[24];
    if (fread(h, 1, sizeof h, f) != sizeof h || le32(h) != PCAP_MAGIC ||
        le32(h + 20) != PCAP_LINKTYPE_RAW) {
        fclose(f);
        return -1;
    }
    uint8_t *buf = malloc(PCAP_SNAPLEN);
    if (!buf) {
        fclose(f);
        return -1;
    }
    long entregues = 0;
    uint8_t r[16];
    while (fread(r, 1, sizeof r, f) == sizeof r) {
        uint32_t tam = le32(r + 8);
        if (tam > PCAP_SNAPLEN) /* registro inválido: não confiamos no tamanho */
            break;
        if (fread(buf, 1, tam, f) != tam)
            break; /* arquivo cortado no meio do registro */
        uint64_t quando = (uint64_t)le32(r) * 1000000 + le32(r + 4);
        entregues++;
        if (fn(ctx, quando, buf, tam))
            break;
    }
    free(buf);
    fclose(f);
    return entregues;
}

/* ---------------------------------------------------------------- filtro por fluxo */

typedef struct {
    const sn_tupla *t;
    uint64_t desde_us, ate_us;
    size_t max;
    long entregues;
    sn_pcap_visita fn;
    void *ctx;
} filtro;

/* O pacote pertence ao fluxo t, em qualquer sentido? */
static int do_fluxo(const sn_tupla *t, const uint8_t *p, size_t n) {
    sn_ip ip;
    if (sn_ip_ler(p, n, &ip) != SN_OK || ip.versao != t->versao || ip.protocolo != t->protocolo)
        return 0;
    const uint8_t *l4 = p + ip.tam_cabecalho;
    if (ip.tam_total - ip.tam_cabecalho < 4)
        return 0;
    sn_tupla do_pacote = sn_tupla_de(&ip, ip.protocolo, be16(l4), be16(l4 + 2));
    sn_tupla volta = sn_tupla_inversa(t);
    return sn_tupla_igual(&do_pacote, t) || sn_tupla_igual(&do_pacote, &volta);
}

static int visita_filtro(void *ctx, uint64_t quando_us, const uint8_t *p, size_t n) {
    filtro *f = ctx;
    /* Os registros vêm em ordem de tempo: passou do fim da conversa (com 10 s de folga),
     * o resto do arquivo não interessa. */
    if (f->ate_us && quando_us > f->ate_us + 10000000u)
        return 1;
    if ((f->desde_us && quando_us < f->desde_us) || (f->ate_us && quando_us > f->ate_us) || !do_fluxo(f->t, p, n))
        return 0;
    f->entregues++;
    if (f->fn(f->ctx, quando_us, p, n))
        return 1;
    return (size_t)f->entregues >= f->max;
}

long sn_pcap_ler_fluxo(const char *caminho, const sn_tupla *t, uint64_t desde_us, uint64_t ate_us,
                       size_t max, sn_pcap_visita fn, void *ctx) {

    if (max == 0)
        return 0;
    filtro f = {.t = t, .desde_us = desde_us, .ate_us = ate_us, .max = max, .fn = fn, .ctx = ctx};
    if (sn_pcap_ler(caminho, visita_filtro, &f) < 0)
        return -1;
    return f.entregues;
}
