/* Mini framework de testes do Sentinela.
 *
 * Uso:
 *   TESTE(ip_le_cabecalho_v4) {
 *       CONFERE(x == 4);
 *       CONFERE_IGUAL_INT(sn_algo(), 20);
 *       CONFERE_IGUAL_MEM(buf, esperado, 16);
 *   }
 *
 * Cada TESTE se registra sozinho (atributo constructor do GCC/Clang), então basta
 * criar o arquivo em tests/. O executável aceita um filtro: ./testes ip roda só
 * os testes cujo nome contém "ip".
 */
#ifndef TESTE_H
#define TESTE_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef void (*sn_teste_fn)(void);

void sn_teste_registrar(const char *nome, sn_teste_fn fn);
void sn_teste_falhou(const char *arquivo, int linha, const char *msg);
void sn_teste_pulou(const char *motivo);

/* Pula o teste de forma visível (aparece como "pulado" com o motivo). */
#define PULA(motivo)                                                    \
    do {                                                                \
        sn_teste_pulou(motivo);                                         \
        return;                                                         \
    } while (0)

#define TESTE(nome)                                                     \
    static void teste_##nome(void);                                     \
    __attribute__((constructor)) static void registra_##nome(void) {    \
        sn_teste_registrar(#nome, teste_##nome);                        \
    }                                                                   \
    static void teste_##nome(void)

#define CONFERE(cond)                                                   \
    do {                                                                \
        if (!(cond)) {                                                  \
            sn_teste_falhou(__FILE__, __LINE__, "CONFERE(" #cond ")");  \
            return;                                                     \
        }                                                               \
    } while (0)

#define CONFERE_IGUAL_INT(obtido, esperado)                             \
    do {                                                                \
        long long o_ = (long long)(obtido), e_ = (long long)(esperado); \
        if (o_ != e_) {                                                 \
            char m_[256];                                               \
            snprintf(m_, sizeof m_, "%s = %lld (0x%llx), esperado %lld (0x%llx)", \
                     #obtido, o_, (unsigned long long)o_, e_,           \
                     (unsigned long long)e_);                           \
            sn_teste_falhou(__FILE__, __LINE__, m_);                    \
            return;                                                     \
        }                                                               \
    } while (0)

#define CONFERE_IGUAL_MEM(obtido, esperado, n)                          \
    do {                                                                \
        if (memcmp((obtido), (esperado), (n)) != 0) {                   \
            sn_teste_falhou(__FILE__, __LINE__,                         \
                            "memória diferente: " #obtido);             \
            return;                                                     \
        }                                                               \
    } while (0)

/* Lê tests/fixtures/<nome>.hex (bytes em hex, espaços e quebras ignorados)
 * para buf. Devolve quantos bytes leu, ou 0 se não achou o arquivo. */
size_t sn_fixture(const char *nome, uint8_t *buf, size_t cap);

#endif
