/* Sentinela — dissecar um pacote em camadas, como o Wireshark (Tarefa 12).
 *
 * Saída em texto, uma linha por campo:
 *   linha 1: "Resumo: <protocolo> <origem> → <destino> <detalhe>"
 *   depois, para cada camada: o nome da camada sem recuo, e os campos com dois espaços:
 *     "IPv4"
 *     "  TTL: 64"
 *   no fim, os dados da aplicação em hex + ASCII (até 256 bytes).
 * Nunca lê fora de p[0..n-1]; pacote cortado ou estranho aparece como "[cortado]"/"[inválido]".
 */
#ifndef SN_DISSECAR_H
#define SN_DISSECAR_H

#include <stddef.h>
#include <stdint.h>

/* Escreve a árvore em `saida` (sempre terminada em '\0', cortada se não couber).
 * Devolve quantos bytes escreveu (sem o '\0'). */
size_t sn_dissecar(const uint8_t *p, size_t n, char *saida, size_t cap);

#endif
