/* Nomes no tráfego: respostas DNS e SNI do TLS. Contrato em include/sn_nomes.h.
 * Aulas 04 (seções 8 e 9) e 07 (por que parser de rede é onde moram as falhas).
 *
 * Os dois parsers usam o mesmo cuidado: posição `i` sempre conferida contra o fim antes
 * de ler, tamanhos declarados conferidos contra o que existe, laços com limite.
 */
#include <ctype.h>
#include <string.h>

#include "bytes.h"
#include "sn_nomes.h"

/* Caractere de nome em minúsculas; fora do ASCII visível vira '?'. */
static char normaliza(uint8_t c) {
    if (c < 0x21 || c > 0x7e)
        return '?';
    return (char)tolower(c);
}

/* ================================================================ DNS (RFC 1035) */

enum {
    DNS_MAX_SALTOS = 32, /* ponteiros de compressão seguidos por nome */
    DNS_TIPO_A = 1,
    DNS_TIPO_AAAA = 28,
    DNS_CLASSE_IN = 1,
};

/* Lê um nome começando em *pos. Rótulos são (tamanho, bytes); 0 encerra; um byte com os
 * dois bits de cima ligados (0xC0) é um ponteiro de 14 bits para outro ponto da mensagem
 * (compressão). *pos avança até logo depois do nome no lugar original (depois do primeiro
 * ponteiro, se houver). Com dst == NULL só pula o nome. */
static int ler_nome(const uint8_t *p, size_t n, size_t *pos, char *dst) {
    size_t i = *pos, fim = 0, len = 0;
    int saltos = 0;
    for (;;) {
        if (i >= n)
            return SN_ERR_CURTO;
        uint8_t c = p[i];
        if (c == 0) {
            i++;
            break;
        }
        if ((c & 0xc0) == 0xc0) {
            if (i + 1 >= n)
                return SN_ERR_CURTO;
            if (saltos == 0)
                fim = i + 2;
            if (++saltos > DNS_MAX_SALTOS)
                return SN_ERR_CABECALHO;
            size_t alvo = (size_t)(c & 0x3f) << 8 | p[i + 1];
            if (alvo >= n)
                return SN_ERR_CABECALHO;
            i = alvo;
            continue;
        }
        if (c & 0xc0) /* 0x40 e 0x80: tipos de rótulo reservados */
            return SN_ERR_CABECALHO;
        if (i + 1 + c > n)
            return SN_ERR_CURTO;
        size_t novo = len + (len ? 1 : 0) + c;
        if (novo > SN_NOME_MAX)
            return SN_ERR_TAMANHO;
        if (dst) {
            if (len)
                dst[len++] = '.';
            for (size_t k = 0; k < c; k++)
                dst[len++] = normaliza(p[i + 1 + k]);
        }
        len = novo;
        i += 1 + (size_t)c;
    }
    if (dst)
        dst[len] = '\0';
    *pos = saltos ? fim : i;
    return SN_OK;
}

int sn_dns_ler_resposta(const uint8_t *p, size_t n, sn_dns_resposta *out) {
    memset(out, 0, sizeof *out);
    if (n < 12)
        return SN_ERR_CURTO;
    out->id = be16(p);
    int resposta = (p[2] & 0x80) != 0; /* bit QR */
    unsigned perguntas = be16(p + 4), respostas = be16(p + 6);
    if (!resposta || perguntas == 0)
        return SN_ERR_FORMATO;

    /* Pergunta: guardamos o nome da primeira (é o que o app pediu). */
    size_t i = 12;
    for (unsigned q = 0; q < perguntas; q++) {
        int r = ler_nome(p, n, &i, q == 0 ? out->nome : NULL);
        if (r != SN_OK)
            return r;
        if (i + 4 > n) /* tipo e classe */
            return SN_ERR_CURTO;
        i += 4;
    }

    /* Respostas: guardamos todo A e AAAA. Registro malformado encerra a leitura, mas o que
     * já foi lido continua valendo (a pergunta já identifica a resposta). */
    for (unsigned a = 0; a < respostas; a++) {
        if (ler_nome(p, n, &i, NULL) != SN_OK || i + 10 > n)
            break;
        unsigned tipo = be16(p + i), classe = be16(p + i + 2);
        size_t tam = be16(p + i + 8);
        i += 10;
        if (i + tam > n)
            break;
        size_t tam_ip = tipo == DNS_TIPO_A ? 4 : tipo == DNS_TIPO_AAAA ? 16 : 0;
        if (classe == DNS_CLASSE_IN && tam_ip && tam == tam_ip &&
            out->n_enderecos < SN_DNS_MAX_ENDERECOS) {
            sn_endereco *e = &out->enderecos[out->n_enderecos++];
            e->versao = tam_ip == 4 ? 4 : 6;
            memcpy(e->ip, p + i, tam_ip);
        }
        i += tam;
    }
    return SN_OK;
}

/* ================================================================ SNI (RFC 8446 / 6066) */

enum {
    TLS_HANDSHAKE = 22,
    TLS_CLIENT_HELLO = 1,
    TLS_EXT_SERVER_NAME = 0,
    TLS_EXT_ECH = 0xfe0d, /* encrypted_client_hello */
    SNI_HOST_NAME = 0,
};

int sn_tls_sni(const uint8_t *p, size_t n, char *nome, size_t cap, int *ech) {
    /* Registro TLS: tipo (1), versão (2), tamanho (2). Depois, a mensagem de handshake:
     * tipo (1), tamanho (3). Decide cedo se é ClientHello, para não esperar à toa. */
    if (n >= 1 && p[0] != TLS_HANDSHAKE)
        return SN_ERR_FORMATO;
    if (n >= 2 && p[1] != 3)
        return SN_ERR_FORMATO;
    if (n >= 6 && p[5] != TLS_CLIENT_HELLO)
        return SN_ERR_FORMATO;
    if (n < 9)
        return SN_ERR_CURTO;
    size_t tam_registro = be16(p + 3);
    size_t tam_hello = (size_t)p[6] << 16 | (size_t)p[7] << 8 | p[8];
    if (tam_hello + 4 > tam_registro)
        return SN_ERR_FORMATO; /* ClientHello em mais de um registro: fora da v1 */
    size_t fim = 9 + tam_hello;
    if (n < fim)
        return SN_ERR_CURTO; /* espera o ClientHello inteiro */

    size_t i = 9 + 2 + 32; /* versão do cliente + random */
    if (i + 1 > fim)
        return SN_ERR_FORMATO;
    i += 1 + (size_t)p[i]; /* session id */
    if (i + 2 > fim)
        return SN_ERR_FORMATO;
    i += 2 + (size_t)be16(p + i); /* cipher suites */
    if (i + 1 > fim)
        return SN_ERR_FORMATO;
    i += 1 + (size_t)p[i]; /* métodos de compressão */
    if (i + 2 > fim)
        return SN_ERR_FORMATO; /* sem extensões, sem SNI */
    size_t fim_ext = i + 2 + be16(p + i);
    if (fim_ext > fim)
        return SN_ERR_FORMATO;
    i += 2;

    /* Percorre todas as extensões: o SNI pode vir antes ou depois da de ECH. */
    int achou = 0, tem_ech = 0;
    while (i + 4 <= fim_ext) {
        unsigned tipo = be16(p + i);
        size_t tam = be16(p + i + 2);
        i += 4;
        if (i + tam > fim_ext)
            return SN_ERR_FORMATO;
        if (tipo == TLS_EXT_ECH)
            tem_ech = 1;
        if (tipo == TLS_EXT_SERVER_NAME && !achou) {
            /* lista (2) de entradas: tipo (1), tamanho (2), nome */
            size_t j = i + 2, fim_lista = i + tam;
            if (j > fim_lista || i + 2 + be16(p + i) > fim_lista)
                return SN_ERR_FORMATO;
            while (j + 3 <= fim_lista && !achou) {
                unsigned tipo_nome = p[j];
                size_t tam_nome = be16(p + j + 1);
                j += 3;
                if (j + tam_nome > fim_lista)
                    return SN_ERR_FORMATO;
                if (tipo_nome == SNI_HOST_NAME) {
                    if (tam_nome == 0 || tam_nome > SN_NOME_MAX)
                        return SN_ERR_FORMATO;
                    if (tam_nome + 1 > cap)
                        return SN_ERR_TAMANHO;
                    for (size_t k = 0; k < tam_nome; k++)
                        nome[k] = normaliza(p[j + k]);
                    nome[tam_nome] = '\0';
                    achou = 1;
                }
                j += tam_nome;
            }
            if (!achou)
                return SN_ERR_FORMATO;
        }
        i += tam;
    }
    if (!achou)
        return SN_ERR_FORMATO;
    if (ech)
        *ech = tem_ech;
    return SN_OK;
}
