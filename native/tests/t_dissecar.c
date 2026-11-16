/* Testes da Tarefa 12: campos e valores conferidos com o `tshark -V` das mesmas fixtures
 * (campo a campo; o texto inteiro não é comparado). */
#include <stdlib.h>

#include "sn_dissecar.h"
#include "teste.h"

static char saida[16384];

static int dissecar_fixture(const char *nome) {
    uint8_t p[2048];
    size_t n = sn_fixture(nome, p, sizeof p);
    if (!n) return 0;
    sn_dissecar(p, n, saida, sizeof saida);
    return 1;
}

static int tem(const char *linha) {
    if (strstr(saida, linha)) return 1;
    fprintf(stderr, "  não achei a linha \"%s\" em:\n%s\n", linha, saida);
    return 0;
}

TESTE(dissecar_ipv4_udp) {
    CONFERE(dissecar_fixture("v4_udp_simples"));
    const char *resumo = "Resumo: UDP 10.111.0.1:40000 → 1.1.1.1:9999";
    CONFERE(strncmp(saida, resumo, strlen(resumo)) == 0);
    CONFERE(tem("\nIPv4\n"));
    CONFERE(tem("  Versão: 4\n"));
    CONFERE(tem("  Tamanho do cabeçalho: 20\n"));  /* tshark: Header Length 20 */
    CONFERE(tem("  Tamanho total: 30\n"));
    CONFERE(tem("  Identificação: 0x1234\n"));
    CONFERE(tem("  TTL: 64\n"));
    CONFERE(tem("  Protocolo: 17 (UDP)\n"));
    CONFERE(tem("  Checksum: 0x5c2a [correto]\n")); /* tshark: 0x5c2a [correct] */
    CONFERE(tem("  Origem: 10.111.0.1\n"));
    CONFERE(tem("  Destino: 1.1.1.1\n"));
    CONFERE(tem("\nUDP\n"));
    CONFERE(tem("  Porta de origem: 40000\n"));
    CONFERE(tem("  Porta de destino: 9999\n"));
    CONFERE(tem("  Tamanho: 10\n"));
    CONFERE(tem("  Checksum: 0xc0af [correto]\n")); /* tshark: 0xc0af [correct] */
    CONFERE(tem("Dados (2 bytes)"));
}

TESTE(dissecar_tcp_syn_com_mss) {
    CONFERE(dissecar_fixture("v4_tcp_syn_mss"));
    CONFERE(tem("[SYN]"));
    CONFERE(tem("\nTCP\n"));
    CONFERE(tem("  Sequência: 1000\n"));
    CONFERE(tem("  Flags: 0x002 (SYN)\n"));      /* tshark: tcp.flags 0x0002 */
    CONFERE(tem("  Janela: 65535\n"));
    CONFERE(tem("  Tamanho do cabeçalho: 32\n"));
    CONFERE(tem("  MSS: 1460\n"));
    CONFERE(tem("  Checksum: 0x88f4 [correto]\n"));
}

TESTE(dissecar_ipv6_tcp_com_dados) {
    CONFERE(dissecar_fixture("v6_tcp_ack_dados"));
    CONFERE(tem("\nIPv6\n"));
    CONFERE(tem("  Hop limit: 64\n"));
    CONFERE(tem("  Origem: fd00:5e:1::1\n"));
    CONFERE(tem("  Destino: 2606:4700:4700::1111\n"));
    CONFERE(tem("  Flags: 0x018 (PSH, ACK)\n"));
    CONFERE(tem("  Confirmação: 2695938256\n"));
    CONFERE(tem("  Checksum: 0x975a [correto]\n"));
    CONFERE(tem("Dados (5 bytes)"));
    CONFERE(tem("hello"));
}

TESTE(dissecar_resposta_dns) {
    CONFERE(dissecar_fixture("dns_cname_a"));
    CONFERE(tem("\nDNS\n"));
    CONFERE(tem("  Tipo: resposta\n"));
    CONFERE(tem("  Nome: www.exemplo.com\n"));
    CONFERE(tem("  Endereço: 93.184.215.14\n"));
    CONFERE(tem("  Endereço: 93.184.215.15\n"));
}

TESTE(dissecar_client_hello_mostra_sni) {
    CONFERE(dissecar_fixture("tls_client_hello_sni"));
    CONFERE(tem("\nTLS ClientHello\n"));
    CONFERE(tem("  SNI: www.exemplo.com.br\n"));
    CONFERE(tem("  ECH: não\n"));
}

TESTE(dissecar_checksum_errado_aparece) {
    uint8_t p[64];
    size_t n = sn_fixture("v4_udp_simples", p, sizeof p);
    p[n - 1] ^= 1; /* muda o payload: o checksum UDP deixa de conferir */
    sn_dissecar(p, n, saida, sizeof saida);
    CONFERE(tem("  Checksum: 0xc0af [errado]\n"));
}

TESTE(dissecar_cortado_e_saida_pequena_nao_estouram) {
    uint8_t p[2048];
    size_t n = sn_fixture("tls_client_hello_sni", p, sizeof p);
    for (size_t k = 0; k < n; k += 7) {
        uint8_t *c = malloc(k ? k : 1);
        memcpy(c, p, k);
        sn_dissecar(c, k, saida, sizeof saida);
        free(c);
    }
    char pequena[40];
    size_t w = sn_dissecar(p, n, pequena, sizeof pequena);
    CONFERE(w < sizeof pequena);
    CONFERE(pequena[w] == '\0');
}
