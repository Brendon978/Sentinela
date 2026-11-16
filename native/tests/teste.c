#include "teste.h"

#include <ctype.h>
#include <stdlib.h>

#define MAX_TESTES 1024

static struct {
    const char *nome;
    sn_teste_fn fn;
} testes[MAX_TESTES];
static int n_testes;
static int falhou_atual;
static const char *pulou_atual;

void sn_teste_pulou(const char *motivo) { pulou_atual = motivo; }

void sn_teste_registrar(const char *nome, sn_teste_fn fn) {
    if (n_testes == MAX_TESTES) {
        fprintf(stderr, "testes demais (máximo %d)\n", MAX_TESTES);
        exit(2);
    }
    testes[n_testes].nome = nome;
    testes[n_testes].fn = fn;
    n_testes++;
}

void sn_teste_falhou(const char *arquivo, int linha, const char *msg) {
    fprintf(stderr, "  FALHOU %s:%d: %s\n", arquivo, linha, msg);
    falhou_atual = 1;
}

static int compara_nome(const void *a, const void *b) {
    const char *const *x = a;
    const char *const *y = b;
    return strcmp(*x, *y);
}

size_t sn_fixture(const char *nome, uint8_t *buf, size_t cap) {
    char caminho[512];
    snprintf(caminho, sizeof caminho, "%s/%s.hex", SN_FIXTURES, nome);
    FILE *f = fopen(caminho, "r");
    if (!f) {
        fprintf(stderr, "  fixture não encontrada: %s\n", caminho);
        return 0;
    }
    size_t n = 0;
    int alto = -1, c;
    while ((c = fgetc(f)) != EOF && n < cap) {
        if (c == '#') { /* comentário até o fim da linha */
            while ((c = fgetc(f)) != EOF && c != '\n') {}
            continue;
        }
        if (!isxdigit(c)) continue;
        int v = isdigit(c) ? c - '0' : (tolower(c) - 'a' + 10);
        if (alto < 0) {
            alto = v;
        } else {
            buf[n++] = (uint8_t)(alto << 4 | v);
            alto = -1;
        }
    }
    fclose(f);
    return n;
}

int main(int argc, char **argv) {
    const char *filtro = argc > 1 ? argv[1] : "";
    /* Ordem estável por nome, para a saída não depender da ordem de link. */
    qsort(testes, (size_t)n_testes, sizeof testes[0], compara_nome);
    int rodados = 0, falhas = 0, pulados = 0;
    for (int i = 0; i < n_testes; i++) {
        if (!strstr(testes[i].nome, filtro)) continue;
        falhou_atual = 0;
        pulou_atual = NULL;
        testes[i].fn();
        rodados++;
        if (pulou_atual && !falhou_atual) {
            pulados++;
            printf("- %s (pulado: %s)\n", testes[i].nome, pulou_atual);
        } else if (falhou_atual) {
            falhas++;
            fprintf(stderr, "x %s\n", testes[i].nome);
        } else {
            printf("ok %s\n", testes[i].nome);
        }
    }
    printf("%d teste%s, %d falha%s", rodados, rodados == 1 ? "" : "s",
           falhas, falhas == 1 ? "" : "s");
    if (pulados)
        printf(", %d pulado%s", pulados, pulados == 1 ? "" : "s");
    printf("\n");
    return falhas ? 1 : (rodados ? 0 : 3);
}
