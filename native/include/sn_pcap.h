/* Sentinela — gravar e ler arquivos .pcap (Tarefa 3).
 *
 * Formato pcap clássico (wiki do Wireshark, "Development/LibpcapFileFormat"): cabeçalho
 * global de 24 bytes (magic 0xa1b2c3d4, versão 2.4, snaplen 65535, linktype 101 = Raw IP)
 * e, para cada pacote, 16 bytes (segundos, microssegundos, tamanho gravado, tamanho
 * original) seguidos dos bytes. Tudo em little-endian (a ordem da máquina que grava;
 * o magic diz qual foi).
 */
#ifndef SN_PCAP_H
#define SN_PCAP_H

#include <stddef.h>
#include <stdint.h>

#include "sn_transporte.h"

typedef struct sn_pcap sn_pcap;

/* Cria (ou trunca) o arquivo e grava o cabeçalho global. NULL em erro (errno diz o motivo). */
sn_pcap *sn_pcap_abrir(const char *caminho);

/* Grava um pacote com o carimbo `quando_us` (microssegundos desde 1970, UTC).
 * Pacotes maiores que 65535 bytes são cortados (o tamanho original fica registrado).
 * Descarrega no disco a cada 256 pacotes ou quando passa 1 s desde a última descarga,
 * medido pelos próprios carimbos. Devolve 0, ou -1 em erro de escrita. */
int sn_pcap_gravar(sn_pcap *pc, uint64_t quando_us, const uint8_t *p, size_t n);

/* Descarrega e fecha. Devolve 0, ou -1 se alguma escrita falhou. Aceita NULL. */
int sn_pcap_fechar(sn_pcap *pc);

/* Chamada para cada pacote lido. Devolver diferente de 0 interrompe a leitura. */
typedef int (*sn_pcap_visita)(void *ctx, uint64_t quando_us, const uint8_t *p, size_t n);

/* Lê o arquivo do começo ao fim. Para no primeiro registro incompleto (arquivo cortado)
 * sem considerar erro. Devolve quantos pacotes foram entregues, ou -1 se o arquivo não
 * abriu ou não é um pcap Raw IP que este módulo grava. */
long sn_pcap_ler(const char *caminho, sn_pcap_visita fn, void *ctx);

/* Como sn_pcap_ler, mas entrega só os pacotes do fluxo `t`, nos dois sentidos
 * (origem e destino trocados também contam), com carimbo em [desde_us, ate_us] (0 = sem
 * limite daquele lado), até `max` pacotes. O intervalo separa duas conversas com a mesma
 * tupla (um fluxo que expirou e outro que nasceu depois). */
long sn_pcap_ler_fluxo(const char *caminho, const sn_tupla *t, uint64_t desde_us, uint64_t ate_us,
                       size_t max, sn_pcap_visita fn, void *ctx);

#endif
