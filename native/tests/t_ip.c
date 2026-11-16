/* Testes da Tarefa 1. Valores esperados tirados do tshark sobre as fixtures
 * (tools/fixtures/oraculo.sh <nome>), nunca do próprio parser. */
#include <stdlib.h>

#include "sn_ip.h"
#include "teste.h"

static const uint8_t IP_10_111_0_1[4] = {10, 111, 0, 1};
static const uint8_t IP_1_1_1_1[4] = {1, 1, 1, 1};
static const uint8_t IP6_FD00_5E_1__1[16] = {0xfd, 0x00, 0x00, 0x5e, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const uint8_t IP6_CLOUDFLARE[16] = {0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11};
static const uint8_t ZEROS[12] = {0};

/* ---------- checksum ---------- */

TESTE(ip_checksum_de_cabecalho_valido_da_zero) {
    uint8_t p[64];
    CONFERE(sn_fixture("v4_udp_simples", p, sizeof p) == 30);
    CONFERE_IGUAL_INT(sn_checksum(p, 20, 0), 0);
}

TESTE(ip_checksum_calcula_o_valor_do_campo) {
    uint8_t p[64];
    CONFERE(sn_fixture("v4_udp_simples", p, sizeof p) == 30);
    p[10] = 0; /* zera o campo checksum (bytes 10 e 11) e recalcula */
    p[11] = 0;
    CONFERE_IGUAL_INT(sn_checksum(p, 20, 0), 0x5c2a); /* tshark: Header Checksum 0x5c2a */
}

TESTE(ip_checksum_com_opcoes) {
    uint8_t p[64];
    CONFERE(sn_fixture("v4_com_opcoes", p, sizeof p) == 44);
    p[10] = 0;
    p[11] = 0;
    CONFERE_IGUAL_INT(sn_checksum(p, 24, 0), 0x3893); /* tshark: 0x3893 */
}

TESTE(ip_checksum_tamanho_impar) {
    /* RFC 1071: byte final sozinho conta como 0xAB00. ~(0xAB00) = 0x54FF */
    const uint8_t p[1] = {0xab};
    CONFERE_IGUAL_INT(sn_checksum(p, 1, 0), 0x54ff);
}

TESTE(ip_checksum_soma_inicial_encadeia) {
    /* Somar tudo de uma vez ou em duas partes (a primeira como soma inicial) dá o mesmo:
     * ~(0x0001 + 0x0002) = 0xFFFC */
    const uint8_t p[2] = {0x00, 0x02};
    CONFERE_IGUAL_INT(sn_checksum(p, 2, 0x0001), 0xfffc);
}

TESTE(ip_checksum_dobra_o_vai_um) {
    /* 0xFFFF + 0xFFFF = 0x1FFFE -> dobra -> 0xFFFF -> complementa -> 0x0000 */
    const uint8_t p[4] = {0xff, 0xff, 0xff, 0xff};
    CONFERE_IGUAL_INT(sn_checksum(p, 4, 0), 0x0000);
    /* 0x8000 + 0x8001 = 0x10001 -> dobra -> 0x0002 -> complementa -> 0xFFFD */
    const uint8_t q[4] = {0x80, 0x00, 0x80, 0x01};
    CONFERE_IGUAL_INT(sn_checksum(q, 4, 0), 0xfffd);
}

/* ---------- IPv4 ---------- */

TESTE(ip_le_v4_udp) {
    uint8_t p[64];
    size_t n = sn_fixture("v4_udp_simples", p, sizeof p);
    sn_ip ip;
    CONFERE_IGUAL_INT(sn_ip_ler(p, n, &ip), SN_OK);
    CONFERE_IGUAL_INT(ip.versao, 4);
    CONFERE_IGUAL_INT(ip.tam_cabecalho, 20);
    CONFERE_IGUAL_INT(ip.tam_total, 30);
    CONFERE_IGUAL_INT(ip.ttl, 64);
    CONFERE_IGUAL_INT(ip.protocolo, 17);
    CONFERE_IGUAL_MEM(ip.origem, IP_10_111_0_1, 4);
    CONFERE_IGUAL_MEM(ip.origem + 4, ZEROS, 12);
    CONFERE_IGUAL_MEM(ip.destino, IP_1_1_1_1, 4);
    CONFERE_IGUAL_MEM(ip.destino + 4, ZEROS, 12);
}

TESTE(ip_le_v4_com_opcoes) {
    uint8_t p[64];
    size_t n = sn_fixture("v4_com_opcoes", p, sizeof p);
    sn_ip ip;
    CONFERE_IGUAL_INT(sn_ip_ler(p, n, &ip), SN_OK);
    CONFERE_IGUAL_INT(ip.tam_cabecalho, 24); /* tshark: Header Length 24 bytes */
    CONFERE_IGUAL_INT(ip.tam_total, 44);
    CONFERE_IGUAL_INT(ip.ttl, 63);
    CONFERE_IGUAL_INT(ip.protocolo, 6);
    const uint8_t dst[4] = {93, 184, 215, 14};
    CONFERE_IGUAL_MEM(ip.destino, dst, 4);
}

TESTE(ip_v4_aceita_sobra_depois_do_pacote) {
    uint8_t p[64] = {0};
    size_t n = sn_fixture("v4_udp_simples", p, sizeof p);
    sn_ip ip;
    CONFERE_IGUAL_INT(sn_ip_ler(p, n + 10, &ip), SN_OK);
    CONFERE_IGUAL_INT(ip.tam_total, 30);
}

TESTE(ip_v4_fragmento_e_recusado) {
    uint8_t p[64];
    size_t n = sn_fixture("v4_fragmento", p, sizeof p);
    sn_ip ip;
    CONFERE_IGUAL_INT(sn_ip_ler(p, n, &ip), SN_ERR_FRAGMENTO);
}

TESTE(ip_v4_offset_de_fragmento_e_recusado) {
    uint8_t p[64];
    size_t n = sn_fixture("v4_udp_simples", p, sizeof p);
    p[7] = 0x08; /* offset 8 (em unidades de 8 bytes), MF desligado: último fragmento */
    sn_ip ip;
    CONFERE_IGUAL_INT(sn_ip_ler(p, n, &ip), SN_ERR_FRAGMENTO);
}

TESTE(ip_v4_ihl_menor_que_5) {
    uint8_t p[64];
    size_t n = sn_fixture("v4_udp_simples", p, sizeof p);
    p[0] = 0x44; /* IHL = 4 -> 16 bytes, abaixo do mínimo */
    sn_ip ip;
    CONFERE_IGUAL_INT(sn_ip_ler(p, n, &ip), SN_ERR_CABECALHO);
}

TESTE(ip_v4_total_maior_que_o_buffer) {
    uint8_t p[64];
    size_t n = sn_fixture("v4_udp_simples", p, sizeof p);
    p[2] = 0x00;
    p[3] = 0x40; /* declara 64 bytes, mas o buffer tem 30 */
    sn_ip ip;
    CONFERE_IGUAL_INT(sn_ip_ler(p, n, &ip), SN_ERR_TAMANHO);
}

TESTE(ip_v4_total_menor_que_o_cabecalho) {
    uint8_t p[64];
    size_t n = sn_fixture("v4_udp_simples", p, sizeof p);
    p[2] = 0x00;
    p[3] = 0x10; /* 16 < 20 */
    sn_ip ip;
    CONFERE_IGUAL_INT(sn_ip_ler(p, n, &ip), SN_ERR_TAMANHO);
}

/* ---------- IPv6 ---------- */

TESTE(ip_le_v6_udp) {
    uint8_t p[128];
    size_t n = sn_fixture("v6_udp_simples", p, sizeof p);
    sn_ip ip;
    CONFERE_IGUAL_INT(sn_ip_ler(p, n, &ip), SN_OK);
    CONFERE_IGUAL_INT(ip.versao, 6);
    CONFERE_IGUAL_INT(ip.tam_cabecalho, 40);
    CONFERE_IGUAL_INT(ip.tam_total, 51); /* tshark: Payload Length 11 + 40 */
    CONFERE_IGUAL_INT(ip.ttl, 64);
    CONFERE_IGUAL_INT(ip.protocolo, 17);
    CONFERE_IGUAL_MEM(ip.origem, IP6_FD00_5E_1__1, 16);
    CONFERE_IGUAL_MEM(ip.destino, IP6_CLOUDFLARE, 16);
}

TESTE(ip_v6_pula_hop_by_hop) {
    uint8_t p[128];
    size_t n = sn_fixture("v6_hop_by_hop", p, sizeof p);
    sn_ip ip;
    CONFERE_IGUAL_INT(sn_ip_ler(p, n, &ip), SN_OK);
    CONFERE_IGUAL_INT(ip.protocolo, 17);     /* tshark: Hop-by-Hop Next Header UDP (17) */
    CONFERE_IGUAL_INT(ip.tam_cabecalho, 48); /* 40 + extensão de 8 bytes */
    CONFERE_IGUAL_INT(ip.tam_total, 59);     /* Payload Length 19 + 40 */
    CONFERE_IGUAL_INT(ip.ttl, 1);
}

TESTE(ip_v6_fragmento_e_recusado) {
    uint8_t p[128];
    size_t n = sn_fixture("v6_fragmento", p, sizeof p);
    sn_ip ip;
    CONFERE_IGUAL_INT(sn_ip_ler(p, n, &ip), SN_ERR_FRAGMENTO);
}

TESTE(ip_v6_extensao_cortada) {
    uint8_t p[128];
    size_t n = sn_fixture("v6_hop_by_hop", p, sizeof p);
    p[41] = 10; /* Hop-by-Hop diz ter (10+1)*8 = 88 bytes: passa do fim do pacote */
    sn_ip ip;
    CONFERE(sn_ip_ler(p, n, &ip) < 0);
}

TESTE(ip_v6_extensoes_demais) {
    /* 9 Destination Options vazias encadeadas (cada uma: next=60, len=0, 6 bytes de PadN). */
    uint8_t p[40 + 9 * 8] = {0};
    p[0] = 0x60;
    p[4] = 0;
    p[5] = 9 * 8; /* Payload Length */
    p[6] = 60;    /* Next Header: Destination Options */
    for (int i = 0; i < 9; i++) {
        uint8_t *e = p + 40 + i * 8;
        e[0] = 60; /* sempre aponta para outra Destination Options */
        e[1] = 0;
        e[2] = 1; /* PadN */
        e[3] = 4;
    }
    sn_ip ip;
    CONFERE_IGUAL_INT(sn_ip_ler(p, sizeof p, &ip), SN_ERR_CABECALHO);
}

/* ---------- entradas inválidas ---------- */

TESTE(ip_versao_desconhecida) {
    uint8_t p[64];
    size_t n = sn_fixture("v4_udp_simples", p, sizeof p);
    p[0] = 0x55;
    sn_ip ip;
    CONFERE_IGUAL_INT(sn_ip_ler(p, n, &ip), SN_ERR_VERSAO);
}

TESTE(ip_buffer_vazio) {
    sn_ip ip;
    uint8_t p[1] = {0x45};
    CONFERE_IGUAL_INT(sn_ip_ler(p, 0, &ip), SN_ERR_CURTO);
}

/* Corta cada fixture em todos os tamanhos menores que o pacote, numa cópia alocada com o
 * tamanho exato: qualquer leitura além do fim vira erro do AddressSanitizer. */
static int corta_em_todos_os_tamanhos(const char *nome) {
    uint8_t p[128];
    size_t n = sn_fixture(nome, p, sizeof p);
    if (n == 0) return 0;
    for (size_t k = 0; k < n; k++) {
        uint8_t *copia = malloc(k ? k : 1);
        memcpy(copia, p, k);
        sn_ip ip;
        int r = sn_ip_ler(copia, k, &ip);
        free(copia);
        if (r >= 0) {
            fprintf(stderr, "  %s cortado em %zu bytes foi aceito\n", nome, k);
            return 0;
        }
    }
    return 1;
}

TESTE(ip_truncado_nunca_le_fora_nem_aceita) {
    CONFERE(corta_em_todos_os_tamanhos("v4_udp_simples"));
    CONFERE(corta_em_todos_os_tamanhos("v4_com_opcoes"));
    CONFERE(corta_em_todos_os_tamanhos("v6_udp_simples"));
    CONFERE(corta_em_todos_os_tamanhos("v6_hop_by_hop"));
}
