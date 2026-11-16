/* Testes da Tarefa 4. Valores esperados do tshark sobre as fixtures; ClientHellos reais
 * do OpenSSL (gerar.py). */
#include <stdlib.h>

#include "sn_nomes.h"
#include "sn_transporte.h"
#include "teste.h"

/* Carrega a fixture e aponta para o payload de transporte (UDP ou TCP). */
static size_t payload(const char *nome, uint8_t *p, size_t cap, const uint8_t **dados) {
    size_t n = sn_fixture(nome, p, cap);
    sn_ip ip;
    if (n == 0 || sn_ip_ler(p, n, &ip) != SN_OK) return 0;
    const uint8_t *l4 = p + ip.tam_cabecalho;
    size_t n4 = ip.tam_total - ip.tam_cabecalho;
    size_t h = 8;
    if (ip.protocolo == SN_PROTO_TCP) {
        sn_tcp t;
        if (sn_tcp_ler(l4, n4, &t) != SN_OK) return 0;
        h = t.tam_cabecalho;
    }
    *dados = l4 + h;
    return n4 - h;
}

/* ---------- DNS ---------- */

TESTE(nomes_dns_cname_e_dois_a) {
    uint8_t p[512];
    const uint8_t *d;
    size_t n = payload("dns_cname_a", p, sizeof p, &d);
    CONFERE(n > 0);
    sn_dns_resposta r;
    CONFERE_IGUAL_INT(sn_dns_ler_resposta(d, n, &r), SN_OK);
    CONFERE_IGUAL_INT(r.id, 0x1234);
    CONFERE(strcmp(r.nome, "www.exemplo.com") == 0);
    CONFERE_IGUAL_INT(r.n_enderecos, 2); /* tshark: dns.a 93.184.215.14, 93.184.215.15 */
    const uint8_t a1[4] = {93, 184, 215, 14}, a2[4] = {93, 184, 215, 15};
    CONFERE_IGUAL_INT(r.enderecos[0].versao, 4);
    CONFERE_IGUAL_MEM(r.enderecos[0].ip, a1, 4);
    CONFERE_IGUAL_MEM(r.enderecos[1].ip, a2, 4);
}

TESTE(nomes_dns_aaaa_com_compressao_e_minusculas) {
    uint8_t p[512];
    const uint8_t *d;
    size_t n = payload("dns_aaaa_comprimido", p, sizeof p, &d);
    CONFERE(n > 0);
    sn_dns_resposta r;
    CONFERE_IGUAL_INT(sn_dns_ler_resposta(d, n, &r), SN_OK);
    CONFERE(strcmp(r.nome, "exemplo.com") == 0); /* tshark: Exemplo.COM; guardamos em minúsculas */
    CONFERE_IGUAL_INT(r.n_enderecos, 1);
    CONFERE_IGUAL_INT(r.enderecos[0].versao, 6);
    const uint8_t v6[16] = {0x26, 0x06, 0x28, 0x00, 0x02, 0x1f, 0xcb, 0x07,
                            0x68, 0x20, 0x80, 0xda, 0xaf, 0x6b, 0x8b, 0x2c};
    CONFERE_IGUAL_MEM(r.enderecos[0].ip, v6, 16);
}

TESTE(nomes_dns_consulta_nao_e_resposta) {
    uint8_t p[512];
    const uint8_t *d;
    size_t n = payload("dns_consulta", p, sizeof p, &d);
    sn_dns_resposta r;
    CONFERE_IGUAL_INT(sn_dns_ler_resposta(d, n, &r), SN_ERR_FORMATO);
}

TESTE(nomes_dns_ponteiro_em_laco) {
    /* cabeçalho de resposta com 1 pergunta cujo nome é um ponteiro para ele mesmo (offset 12) */
    const uint8_t d[] = {0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1};
    sn_dns_resposta r;
    CONFERE(sn_dns_ler_resposta(d, sizeof d, &r) < 0);
}

TESTE(nomes_dns_ponteiros_alternados) {
    /* nome em 12 aponta para 14, que aponta para 12: laço de dois saltos */
    const uint8_t d[] = {0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0e, 0xc0, 0x0c, 0, 1, 0, 1};
    sn_dns_resposta r;
    CONFERE(sn_dns_ler_resposta(d, sizeof d, &r) < 0);
}

TESTE(nomes_dns_ponteiro_para_fora) {
    const uint8_t d[] = {0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0xff, 0, 1, 0, 1};
    sn_dns_resposta r;
    CONFERE(sn_dns_ler_resposta(d, sizeof d, &r) < 0);
}

TESTE(nomes_dns_nome_gigante) {
    /* 5 rótulos de 63 letras = 319 caracteres com os pontos, acima de 253 */
    uint8_t d[12 + 5 * 64 + 1 + 4] = {0x12, 0x34, 0x81, 0x80, 0, 1};
    size_t i = 12;
    for (int r = 0; r < 5; r++) {
        d[i++] = 63;
        memset(d + i, 'a', 63);
        i += 63;
    }
    d[i++] = 0;
    d[i++] = 0; d[i++] = 1; d[i++] = 0; d[i++] = 1;
    sn_dns_resposta r;
    CONFERE(sn_dns_ler_resposta(d, i, &r) < 0);
}

TESTE(nomes_dns_mais_enderecos_que_o_limite) {
    /* resposta com 20 registros A para o nome da pergunta (ponteiro c0 0c) */
    uint8_t d[512] = {0x12, 0x34, 0x81, 0x80, 0, 1, 0, 20, 0, 0, 0, 0};
    size_t i = 12;
    const uint8_t nome[] = {1, 'x', 0};
    memcpy(d + i, nome, sizeof nome);
    i += sizeof nome;
    d[i++] = 0; d[i++] = 1; d[i++] = 0; d[i++] = 1;
    for (int k = 0; k < 20; k++) {
        const uint8_t rr[] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, (uint8_t)k};
        memcpy(d + i, rr, sizeof rr);
        i += sizeof rr;
    }
    sn_dns_resposta r;
    CONFERE_IGUAL_INT(sn_dns_ler_resposta(d, i, &r), SN_OK);
    CONFERE_IGUAL_INT(r.n_enderecos, SN_DNS_MAX_ENDERECOS);
    CONFERE_IGUAL_INT(r.enderecos[15].ip[3], 15);
}

static int dns_cortado(const char *nome) {
    uint8_t p[512];
    const uint8_t *d;
    size_t n = payload(nome, p, sizeof p, &d);
    if (n == 0) return 0;
    for (size_t k = 0; k < n; k++) {
        uint8_t *c = malloc(k ? k : 1);
        memcpy(c, d, k);
        sn_dns_resposta r;
        sn_dns_ler_resposta(c, k, &r); /* pode aceitar ou recusar; não pode ler fora */
        free(c);
    }
    return 1;
}

TESTE(nomes_dns_truncado_nunca_le_fora) {
    CONFERE(dns_cortado("dns_cname_a"));
    CONFERE(dns_cortado("dns_aaaa_comprimido"));
}

/* ---------- SNI ---------- */

TESTE(nomes_sni_client_hello_real) {
    uint8_t p[2048];
    const uint8_t *d;
    size_t n = payload("tls_client_hello_sni", p, sizeof p, &d);
    CONFERE_IGUAL_INT(n, 1534); /* tshark: tcp.len 1534 */
    char nome[SN_NOME_MAX + 1];
    CONFERE_IGUAL_INT(sn_tls_sni(d, n, nome, sizeof nome, NULL), SN_OK);
    CONFERE(strcmp(nome, "www.exemplo.com.br") == 0);
}

TESTE(nomes_sni_com_ech_e_marcado) {
    uint8_t p[2048];
    const uint8_t *d;
    size_t n = payload("tls_client_hello_ech", p, sizeof p, &d);
    char nome[SN_NOME_MAX + 1];
    int ech = 0;
    CONFERE_IGUAL_INT(sn_tls_sni(d, n, nome, sizeof nome, &ech), SN_OK);
    CONFERE(strcmp(nome, "cloudflare-ech.com") == 0); /* tshark: SNI cloudflare-ech.com */
    CONFERE_IGUAL_INT(ech, 1);                        /* tshark: encrypted_client_hello presente */
}

TESTE(nomes_sni_sem_ech_nao_e_marcado) {
    uint8_t p[2048];
    const uint8_t *d;
    size_t n = payload("tls_client_hello_sni", p, sizeof p, &d);
    char nome[SN_NOME_MAX + 1];
    int ech = 1;
    CONFERE_IGUAL_INT(sn_tls_sni(d, n, nome, sizeof nome, &ech), SN_OK);
    CONFERE_IGUAL_INT(ech, 0);
}

TESTE(nomes_sni_ausente) {
    uint8_t p[2048];
    const uint8_t *d;
    size_t n = payload("tls_client_hello_sem_sni", p, sizeof p, &d);
    char nome[SN_NOME_MAX + 1];
    CONFERE_IGUAL_INT(sn_tls_sni(d, n, nome, sizeof nome, NULL), SN_ERR_FORMATO);
}

TESTE(nomes_sni_partido_pede_mais_bytes) {
    /* O ClientHello de 1534 bytes não cabe num segmento de 1460: em qualquer corte, a
     * resposta tem de ser "faltam bytes" (ou já achou, se o SNI estiver antes do corte). */
    uint8_t p[2048];
    const uint8_t *d;
    size_t n = payload("tls_client_hello_sni", p, sizeof p, &d);
    for (size_t k = 0; k < n; k++) {
        uint8_t *c = malloc(k ? k : 1);
        memcpy(c, d, k);
        char nome[SN_NOME_MAX + 1];
        int r = sn_tls_sni(c, k, nome, sizeof nome, NULL);
        free(c);
        if (r != SN_ERR_CURTO && !(r == SN_OK && strcmp(nome, "www.exemplo.com.br") == 0)) {
            fprintf(stderr, "  corte em %zu bytes devolveu %d\n", k, r);
            CONFERE(0);
        }
    }
}

TESTE(nomes_sni_nao_e_tls) {
    const char *http = "GET / HTTP/1.1\r\nHost: exemplo.com\r\n\r\n";
    char nome[64];
    CONFERE_IGUAL_INT(sn_tls_sni((const uint8_t *)http, strlen(http), nome, sizeof nome, NULL), SN_ERR_FORMATO);
}

TESTE(nomes_sni_nome_nao_cabe) {
    uint8_t p[2048];
    const uint8_t *d;
    size_t n = payload("tls_client_hello_sni", p, sizeof p, &d);
    char nome[8];
    CONFERE_IGUAL_INT(sn_tls_sni(d, n, nome, sizeof nome, NULL), SN_ERR_TAMANHO);
}
