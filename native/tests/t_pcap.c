/* Testes da Tarefa 3. O esperado é o pcap_tres.pcap gerado em Python (gerar.py) e
 * conferido pelo capinfos/tshark: 3 pacotes, Raw IP, carimbos .000001, .5 e 1.0 s. */
#include <stdlib.h>
#include <unistd.h>

#include "sn_pcap.h"
#include "teste.h"

static const uint64_t T0 = 1700000000ull * 1000000ull;

static int le_arquivo(const char *caminho, uint8_t *buf, size_t cap, size_t *n) {
    FILE *f = fopen(caminho, "rb");
    if (!f) return 0;
    *n = fread(buf, 1, cap, f);
    fclose(f);
    return 1;
}

static void temporario(char *caminho, size_t cap) {
    snprintf(caminho, cap, "%s/sn-pcap-XXXXXX", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
    int fd = mkstemp(caminho);
    if (fd >= 0) close(fd);
}

TESTE(pcap_grava_igual_ao_esperado) {
    uint8_t a[64], b[64], c[64];
    size_t na = sn_fixture("v4_udp_simples", a, sizeof a);
    size_t nb = sn_fixture("v6_udp_simples", b, sizeof b);
    size_t nc = sn_fixture("v4_tcp_syn_mss", c, sizeof c);
    char caminho[256];
    temporario(caminho, sizeof caminho);

    sn_pcap *pc = sn_pcap_abrir(caminho);
    CONFERE(pc != NULL);
    CONFERE_IGUAL_INT(sn_pcap_gravar(pc, T0 + 1, a, na), 0);
    CONFERE_IGUAL_INT(sn_pcap_gravar(pc, T0 + 500000, b, nb), 0);
    CONFERE_IGUAL_INT(sn_pcap_gravar(pc, T0 + 1000000, c, nc), 0);
    CONFERE_IGUAL_INT(sn_pcap_fechar(pc), 0);

    uint8_t obtido[512], esperado[512];
    size_t no, ne;
    CONFERE(le_arquivo(caminho, obtido, sizeof obtido, &no));
    CONFERE(le_arquivo(SN_FIXTURES "/pcap_tres.pcap", esperado, sizeof esperado, &ne));
    unlink(caminho);
    CONFERE_IGUAL_INT(no, ne);
    CONFERE_IGUAL_MEM(obtido, esperado, ne);
}

typedef struct {
    int n;
    uint64_t quando[8];
    size_t tam[8];
} coleta;

static int coletar(void *ctx, uint64_t quando_us, const uint8_t *p, size_t n) {
    (void)p;
    coleta *c = ctx;
    if (c->n < 8) {
        c->quando[c->n] = quando_us;
        c->tam[c->n] = n;
    }
    c->n++;
    return 0;
}

TESTE(pcap_le_os_tres) {
    coleta c = {0};
    CONFERE_IGUAL_INT(sn_pcap_ler(SN_FIXTURES "/pcap_tres.pcap", coletar, &c), 3);
    CONFERE_IGUAL_INT(c.n, 3);
    CONFERE_IGUAL_INT(c.quando[0], T0 + 1);
    CONFERE_IGUAL_INT(c.quando[1], T0 + 500000);
    CONFERE_IGUAL_INT(c.quando[2], T0 + 1000000);
    CONFERE_IGUAL_INT(c.tam[0], 30); /* tshark: frame.len 30, 51, 52 */
    CONFERE_IGUAL_INT(c.tam[1], 51);
    CONFERE_IGUAL_INT(c.tam[2], 52);
}

static int para_no_primeiro(void *ctx, uint64_t q, const uint8_t *p, size_t n) {
    (void)q; (void)p; (void)n;
    (*(int *)ctx)++;
    return 1;
}

TESTE(pcap_visita_pode_interromper) {
    int vistos = 0;
    sn_pcap_ler(SN_FIXTURES "/pcap_tres.pcap", para_no_primeiro, &vistos);
    CONFERE_IGUAL_INT(vistos, 1);
}

TESTE(pcap_arquivo_cortado_entrega_so_os_inteiros) {
    uint8_t buf[512];
    size_t n;
    CONFERE(le_arquivo(SN_FIXTURES "/pcap_tres.pcap", buf, sizeof buf, &n));
    char caminho[256];
    temporario(caminho, sizeof caminho);
    /* corta no meio do terceiro registro: 24 + (16+30) + (16+51) + 10 bytes */
    FILE *f = fopen(caminho, "wb");
    CONFERE(f != NULL);
    fwrite(buf, 1, 24 + 46 + 67 + 10, f);
    fclose(f);
    coleta c = {0};
    long r = sn_pcap_ler(caminho, coletar, &c);
    unlink(caminho);
    CONFERE_IGUAL_INT(r, 2);
}

TESTE(pcap_recusa_arquivo_que_nao_e_pcap) {
    coleta c = {0};
    CONFERE_IGUAL_INT(sn_pcap_ler(SN_FIXTURES "/v4_udp_simples.hex", coletar, &c), -1);
    CONFERE_IGUAL_INT(sn_pcap_ler("/caminho/que/nao/existe.pcap", coletar, &c), -1);
}

TESTE(pcap_filtra_fluxo_nos_dois_sentidos) {
    /* fluxo do v4_udp_simples: 10.111.0.1:40000 -> 1.1.1.1:9999 */
    sn_tupla t = {.versao = 4, .protocolo = SN_PROTO_UDP, .porta_origem = 40000, .porta_destino = 9999,
                  .ip_origem = {10, 111, 0, 1}, .ip_destino = {1, 1, 1, 1}};
    coleta c = {0};
    CONFERE_IGUAL_INT(sn_pcap_ler_fluxo(SN_FIXTURES "/pcap_tres.pcap", &t, 0, 0, 10, coletar, &c), 1);
    CONFERE_IGUAL_INT(c.tam[0], 30);

    sn_tupla volta = {.versao = 4, .protocolo = SN_PROTO_UDP, .porta_origem = 9999, .porta_destino = 40000,
                      .ip_origem = {1, 1, 1, 1}, .ip_destino = {10, 111, 0, 1}};
    coleta d = {0};
    CONFERE_IGUAL_INT(sn_pcap_ler_fluxo(SN_FIXTURES "/pcap_tres.pcap", &volta, 0, 0, 10, coletar, &d), 1);

    sn_tupla outro = t;
    outro.porta_destino = 53;
    coleta e = {0};
    CONFERE_IGUAL_INT(sn_pcap_ler_fluxo(SN_FIXTURES "/pcap_tres.pcap", &outro, 0, 0, 10, coletar, &e), 0);
}

TESTE(pcap_corta_pacote_maior_que_o_snaplen) {
    char caminho[256];
    temporario(caminho, sizeof caminho);
    size_t grande = 70000;
    uint8_t *p = calloc(1, grande);
    sn_pcap *pc = sn_pcap_abrir(caminho);
    int r = pc ? sn_pcap_gravar(pc, T0, p, grande) : -1;
    sn_pcap_fechar(pc);
    free(p); /* antes de qualquer CONFERE, que retorna cedo */
    CONFERE_IGUAL_INT(r, 0);
    uint8_t reg[40];
    size_t n;
    CONFERE(le_arquivo(caminho, reg, sizeof reg, &n));
    unlink(caminho);
    /* registro: incl_len = 65535 (ff ff 00 00), orig_len = 70000 (70 11 01 00) */
    const uint8_t incl[4] = {0xff, 0xff, 0x00, 0x00}, orig[4] = {0x70, 0x11, 0x01, 0x00};
    CONFERE_IGUAL_MEM(reg + 24 + 8, incl, 4);
    CONFERE_IGUAL_MEM(reg + 24 + 12, orig, 4);
}

TESTE(pcap_filtra_fluxo_pelo_intervalo_de_tempo) {
    /* Mesma tupla em duas conversas (o fluxo expirou e nasceu outro): o intervalo separa. */
    sn_tupla t = {.versao = 4, .protocolo = SN_PROTO_UDP, .porta_origem = 40000, .porta_destino = 9999,
                  .ip_origem = {10, 111, 0, 1}, .ip_destino = {1, 1, 1, 1}};
    coleta c = {0};
    /* o pacote do fluxo tem carimbo T0+1 */
    CONFERE_IGUAL_INT(sn_pcap_ler_fluxo(SN_FIXTURES "/pcap_tres.pcap", &t, T0 + 2, 0, 10, coletar, &c), 0);
    coleta d = {0};
    CONFERE_IGUAL_INT(sn_pcap_ler_fluxo(SN_FIXTURES "/pcap_tres.pcap", &t, T0, T0, 10, coletar, &d), 0);
    coleta e = {0};
    CONFERE_IGUAL_INT(sn_pcap_ler_fluxo(SN_FIXTURES "/pcap_tres.pcap", &t, T0 + 1, T0 + 1, 10, coletar, &e), 1);
}
