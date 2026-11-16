/* Sentinela — tabela de fluxos (Tarefa 5).
 *
 * Um fluxo é uma conversa app ↔ servidor, identificada pela 5-tupla vista do lado do app:
 * origem = o app (endereço do tun), destino = o servidor. Pacotes que chegam pelo tun são
 * sempre nesse sentido; as respostas chegam pelos sockets do motor, que já sabem a que
 * fluxo pertencem. Por isso a busca é só no sentido app → servidor.
 *
 * O relógio é sempre passado por quem chama (agora_us), nunca lido aqui dentro: assim os
 * testes controlam o tempo. Os prazos usam um relógio monotônico (que não volta quando o
 * Android acerta a hora); só inicio_us e fim_us são hora de parede.
 */
#ifndef SN_FLUXOS_H
#define SN_FLUXOS_H

#include <stddef.h>
#include <stdint.h>

#include "sn_transporte.h"

/* Prazos de expiração. */
#define SN_UDP_OCIOSO_US (60ull * 1000000)          /* UDP sem tráfego */
#define SN_TCP_FECHADO_US (10ull * 1000000)         /* TCP depois de fechado */
#define SN_TCP_OCIOSO_US (2ull * 3600 * 1000000)    /* TCP sem tráfego */

/* Motivos de fim (mesmos valores do evento EV_FLUXO_FIM). */
enum {
    SN_FIM_FECHADO = 0,
    SN_FIM_RESET = 1,
    SN_FIM_TEMPO = 2,
    SN_FIM_ERRO = 3,
};

typedef struct sn_fluxo {
    uint32_t id;           /* sequencial a partir de 1, nunca reaproveitado */
    sn_tupla tupla;
    uint64_t inicio_us;    /* hora de parede (1970) do início; inserir põe `agora`, o motor corrige */
    uint64_t ultimo_us;    /* relógio monotônico do último tráfego; quem chama atualiza */
    uint64_t bytes_env;    /* app → servidor (payload de transporte) */
    uint64_t bytes_rec;    /* servidor → app */
    uint32_t pacotes;
    int fechado;           /* 1 = conversa encerrada; sai depois de SN_TCP_FECHADO_US */
    uint64_t fechado_us;   /* relógio monotônico do fechamento */
    uint64_t fim_us;       /* hora de parede do fechamento (para o evento de fim) */
    uint8_t motivo_fim;    /* SN_FIM_*, vale quando fechado */
    void *estado;          /* do relé (socket, máquina TCP...); a tabela não mexe */
    struct sn_fluxo *prox; /* uso interno da tabela */
} sn_fluxo;

typedef struct sn_fluxos sn_fluxos;

/* Chamada quando um fluxo sai da tabela (expirado ou na destruição), antes do free. */
typedef void (*sn_fluxo_saida)(void *ctx, sn_fluxo *f, uint8_t motivo);

sn_fluxos *sn_fluxos_criar(void);
/* Chama `saida` (se não NULL) para cada fluxo restante, com SN_FIM_FECHADO, e libera tudo. */
void sn_fluxos_destruir(sn_fluxos *t, sn_fluxo_saida saida, void *ctx);

/* Os ponteiros devolvidos ficam válidos até o fluxo sair da tabela. */
sn_fluxo *sn_fluxos_achar(const sn_fluxos *t, const sn_tupla *k);
/* Insere um fluxo novo (não confere duplicata: chame achar antes). NULL sem memória. */
sn_fluxo *sn_fluxos_inserir(sn_fluxos *t, const sn_tupla *k, uint64_t agora_us);
/* Tira da tabela e libera, sem chamar `saida`. */
void sn_fluxos_remover(sn_fluxos *t, sn_fluxo *f);

/* Remove os expirados, chamando `saida` para cada um com o motivo:
 * - fechado há SN_TCP_FECHADO_US ou mais (UDP ou TCP): motivo_fim do fluxo;
 * - UDP aberto sem tráfego há SN_UDP_OCIOSO_US ou mais: SN_FIM_TEMPO;
 * - TCP aberto sem tráfego há SN_TCP_OCIOSO_US ou mais: SN_FIM_TEMPO.
 * Devolve quantos saíram. */
size_t sn_fluxos_expirar(sn_fluxos *t, uint64_t agora_us, sn_fluxo_saida saida, void *ctx);

size_t sn_fluxos_quantos(const sn_fluxos *t);

/* Visita todos os fluxos (ordem qualquer). A visita não pode inserir nem remover. */
void sn_fluxos_cada(const sn_fluxos *t, void (*fn)(void *ctx, sn_fluxo *f), void *ctx);

#endif
