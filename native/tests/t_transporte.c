/* Testes da Tarefa 2. Valores esperados do tshark; pacotes montados comparados byte a
 * byte com os do scapy (tools/fixtures/gerar.py, fixtures montar_*). */
#include <stdlib.h>

#include "sn_transporte.h"
#include "teste.h"

static const uint8_t V4_10_111_0_1[16] = {10, 111, 0, 1};
static const uint8_t V4_93_184_215_14[16] = {93, 184, 215, 14};
static const uint8_t V4_1_1_1_1[16] = {1, 1, 1, 1};
static const uint8_t V6_FD00[16] = {0xfd, 0, 0, 0x5e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const uint8_t V6_CF[16] = {0x26, 6, 0x47, 0, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11};

/* Lê a fixture e o cabeçalho IP; devolve o tamanho (0 em erro). */
static size_t carrega(const char *nome, uint8_t *p, size_t cap, sn_ip *ip) {
    size_t n = sn_fixture(nome, p, cap);
    if (n == 0 || sn_ip_ler(p, n, ip) != SN_OK) return 0;
    return n;
}

/* ---------- leitura ---------- */

TESTE(transporte_le_udp_v4) {
    uint8_t p[128];
    sn_ip ip;
    CONFERE(carrega("v4_udp_simples", p, sizeof p, &ip));
    sn_udp u;
    CONFERE_IGUAL_INT(sn_udp_ler(p + ip.tam_cabecalho, ip.tam_total - ip.tam_cabecalho, &u), SN_OK);
    CONFERE_IGUAL_INT(u.porta_origem, 40000);
    CONFERE_IGUAL_INT(u.porta_destino, 9999);
    CONFERE_IGUAL_INT(u.tamanho, 10);
}

TESTE(transporte_le_tcp_syn_com_mss) {
    uint8_t p[128];
    sn_ip ip;
    CONFERE(carrega("v4_tcp_syn_mss", p, sizeof p, &ip));
    sn_tcp t;
    CONFERE_IGUAL_INT(sn_tcp_ler(p + ip.tam_cabecalho, ip.tam_total - ip.tam_cabecalho, &t), SN_OK);
    CONFERE_IGUAL_INT(t.porta_origem, 40010);
    CONFERE_IGUAL_INT(t.porta_destino, 443);
    CONFERE_IGUAL_INT(t.seq, 1000);
    CONFERE_IGUAL_INT(t.flags, SN_TCP_SYN);
    CONFERE_IGUAL_INT(t.janela, 65535);
    CONFERE_IGUAL_INT(t.tam_cabecalho, 32); /* tshark: Header Length 32 */
    CONFERE_IGUAL_INT(t.mss, 1460);
}

TESTE(transporte_le_tcp_v6_sem_mss) {
    uint8_t p[128];
    sn_ip ip;
    CONFERE(carrega("v6_tcp_ack_dados", p, sizeof p, &ip));
    sn_tcp t;
    CONFERE_IGUAL_INT(sn_tcp_ler(p + ip.tam_cabecalho, ip.tam_total - ip.tam_cabecalho, &t), SN_OK);
    CONFERE_IGUAL_INT(t.seq, 16909060u);   /* 0x01020304 */
    CONFERE_IGUAL_INT(t.ack, 2695938256u); /* 0xA0B0C0D0 */
    CONFERE_IGUAL_INT(t.flags, SN_TCP_PSH | SN_TCP_ACK);
    CONFERE_IGUAL_INT(t.janela, 4096);
    CONFERE_IGUAL_INT(t.tam_cabecalho, 20);
    CONFERE_IGUAL_INT(t.mss, 0);
}

TESTE(transporte_tcp_offset_invalido) {
    uint8_t p[128];
    sn_ip ip;
    CONFERE(carrega("v6_tcp_ack_dados", p, sizeof p, &ip));
    uint8_t *tcp = p + ip.tam_cabecalho;
    size_t n = ip.tam_total - ip.tam_cabecalho;
    sn_tcp t;
    tcp[12] = 0x40; /* Data Offset 4 = 16 bytes, abaixo do mínimo */
    CONFERE(sn_tcp_ler(tcp, n, &t) < 0);
    tcp[12] = 0xf0; /* 60 bytes, mais que os 25 disponíveis */
    CONFERE(sn_tcp_ler(tcp, n, &t) < 0);
}

TESTE(transporte_tcp_opcao_cortada_nao_estoura) {
    uint8_t p[128];
    sn_ip ip;
    CONFERE(carrega("v4_tcp_syn_mss", p, sizeof p, &ip));
    uint8_t *tcp = p + ip.tam_cabecalho;
    tcp[20] = 2;  /* MSS... */
    tcp[21] = 40; /* ...dizendo ter 40 bytes, além do fim das opções */
    sn_tcp t;
    CONFERE(sn_tcp_ler(tcp, ip.tam_total - ip.tam_cabecalho, &t) <= 0);
}

TESTE(transporte_udp_tamanho_maior_que_o_buffer) {
    uint8_t p[128];
    sn_ip ip;
    CONFERE(carrega("v4_udp_simples", p, sizeof p, &ip));
    uint8_t *udp = p + ip.tam_cabecalho;
    udp[4] = 0;
    udp[5] = 50;
    sn_udp u;
    CONFERE(sn_udp_ler(udp, ip.tam_total - ip.tam_cabecalho, &u) < 0);
}

static int corta(const char *nome, int tcp) {
    uint8_t p[128];
    sn_ip ip;
    if (!carrega(nome, p, sizeof p, &ip)) return 0;
    size_t n = ip.tam_total - ip.tam_cabecalho;
    size_t minimo = tcp ? 20 : 8;
    for (size_t k = 0; k < minimo; k++) {
        uint8_t *c = malloc(k ? k : 1);
        memcpy(c, p + ip.tam_cabecalho, k);
        int r = tcp ? sn_tcp_ler(c, k, &(sn_tcp){0}) : sn_udp_ler(c, k, &(sn_udp){0});
        free(c);
        if (r >= 0) return 0;
    }
    (void)n;
    return 1;
}

TESTE(transporte_truncado_nunca_le_fora) {
    CONFERE(corta("v4_udp_simples", 0));
    CONFERE(corta("v4_tcp_syn_mss", 1));
    CONFERE(corta("v6_tcp_ack_dados", 1));
}

/* ---------- checksum com pseudo-cabeçalho ---------- */

TESTE(transporte_checksum_confere_nas_fixtures) {
    const char *nomes[] = {"v4_udp_simples", "v6_udp_simples", "v6_hop_by_hop",
                           "v4_tcp_syn_mss", "v6_tcp_ack_dados"};
    for (size_t i = 0; i < sizeof nomes / sizeof nomes[0]; i++) {
        uint8_t p[128];
        sn_ip ip;
        CONFERE(carrega(nomes[i], p, sizeof p, &ip));
        if (!sn_transporte_checksum_ok(p, &ip)) {
            fprintf(stderr, "  checksum não confere em %s\n", nomes[i]);
            CONFERE(0);
        }
    }
}

TESTE(transporte_checksum_detecta_alteracao) {
    uint8_t p[128];
    sn_ip ip;
    CONFERE(carrega("v6_tcp_ack_dados", p, sizeof p, &ip));
    p[ip.tam_total - 1] ^= 0x01; /* muda um bit do último byte de dados */
    CONFERE(!sn_transporte_checksum_ok(p, &ip));
}

/* ---------- montagem (comparada byte a byte com o scapy) ---------- */

static int confere_montado(const char *nome, const uint8_t *buf, size_t n) {
    uint8_t esperado[256];
    size_t m = sn_fixture(nome, esperado, sizeof esperado);
    if (m != n) {
        fprintf(stderr, "  %s: tamanho %zu, esperado %zu\n", nome, n, m);
        return 0;
    }
    for (size_t i = 0; i < n; i++)
        if (buf[i] != esperado[i]) {
            fprintf(stderr, "  %s: byte %zu = %02x, esperado %02x\n", nome, i, buf[i], esperado[i]);
            return 0;
        }
    return 1;
}

TESTE(transporte_monta_udp_v4) {
    sn_tupla t = {.versao = 4, .protocolo = SN_PROTO_UDP, .porta_origem = 53, .porta_destino = 40000};
    memcpy(t.ip_origem, V4_1_1_1_1, 16);
    memcpy(t.ip_destino, V4_10_111_0_1, 16);
    uint8_t buf[256];
    size_t n = sn_montar_udp(buf, sizeof buf, &t, (const uint8_t *)"resposta", 8);
    CONFERE(confere_montado("montar_v4_udp", buf, n));
}

TESTE(transporte_monta_udp_v6) {
    sn_tupla t = {.versao = 6, .protocolo = SN_PROTO_UDP, .porta_origem = 9999, .porta_destino = 40003};
    memcpy(t.ip_origem, V6_CF, 16);
    memcpy(t.ip_destino, V6_FD00, 16);
    uint8_t buf[256];
    size_t n = sn_montar_udp(buf, sizeof buf, &t, (const uint8_t *)"ok", 2);
    CONFERE(confere_montado("montar_v6_udp", buf, n));
}

TESTE(transporte_monta_synack_v4_com_mss) {
    sn_tupla t = {.versao = 4, .protocolo = SN_PROTO_TCP, .porta_origem = 443, .porta_destino = 40010};
    memcpy(t.ip_origem, V4_93_184_215_14, 16);
    memcpy(t.ip_destino, V4_10_111_0_1, 16);
    uint8_t buf[256];
    size_t n = sn_montar_tcp(buf, sizeof buf, &t, 5000, 1001, SN_TCP_SYN | SN_TCP_ACK, 65535, 1460, NULL, 0);
    CONFERE(confere_montado("montar_v4_synack", buf, n));
}

TESTE(transporte_monta_dados_tcp_v6) {
    sn_tupla t = {.versao = 6, .protocolo = SN_PROTO_TCP, .porta_origem = 80, .porta_destino = 40011};
    memcpy(t.ip_origem, V6_CF, 16);
    memcpy(t.ip_destino, V6_FD00, 16);
    uint8_t buf[256];
    size_t n = sn_montar_tcp(buf, sizeof buf, &t, 7, 9, SN_TCP_PSH | SN_TCP_ACK, 8192, 0,
                             (const uint8_t *)"oi mundo", 8);
    CONFERE(confere_montado("montar_v6_dados", buf, n));
}

TESTE(transporte_monta_recusa_buffer_pequeno) {
    sn_tupla t = {.versao = 6, .protocolo = SN_PROTO_UDP, .porta_origem = 1, .porta_destino = 2};
    uint8_t buf[49]; /* precisa de 40 + 8 + 2 = 50 */
    CONFERE_IGUAL_INT(sn_montar_udp(buf, sizeof buf, &t, (const uint8_t *)"ok", 2), 0);
}
