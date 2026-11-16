# Tarefa 1 — checksum e cabeçalhos IP

**Você escreve:** `native/src/checksum.c` e `native/src/ip.c` (hoje são esqueletos com `TODO(Brendon)`).
**Contrato:** `native/include/sn_ip.h`. Leia os comentários: eles são a especificação.
**Testes:** `native/tests/t_ip.c`. Rode com `tools/testes-c.sh ip`. Hoje: 22 testes, 19 falhas.

## Ordem sugerida

1. `sn_checksum`: faz passar os 6 testes `ip_checksum_*`.
2. IPv4 em `sn_ip_ler`: `ip_le_v4_*` e `ip_v4_*`.
3. IPv6 simples: `ip_le_v6_udp`.
4. Extensões IPv6: `ip_v6_*`.
5. Por último, `ip_truncado_nunca_le_fora_nem_aceita`: se algo seu ler fora do buffer, o
   AddressSanitizer para tudo e mostra a linha.

Rode só um grupo por vez: `tools/testes-c.sh ip_checksum`.

## O que ler (curto)

- **RFC 791, §3.1:** o desenho do cabeçalho IPv4 (aquela tabela de bits). Os campos que importam
  aqui: Version, IHL, Total Length, Flags/Fragment Offset, TTL, Protocol, Source, Destination.
- **RFC 8200, §3 e §4:** cabeçalho IPv6 (40 bytes fixos) e as extensões. Note que o "Hdr Ext Len"
  conta em blocos de 8 bytes, **sem contar os 8 primeiros**: tamanho = (valor + 1) × 8.
- **RFC 1071, §1 e §4.1:** o checksum. O código de exemplo em C da §4.1 é quase a resposta. Leia,
  entenda e escreva o seu.

## Conceitos que esta tarefa ensina

- **Ordem de bytes (endianness).** Na rede tudo é big-endian. `Total Length` nos bytes 2 e 3 é
  `p[2] << 8 | p[3]`. Faça assim, montando byte a byte, em vez de `ntohs(*(uint16_t*)(p+2))`.
- **Por que não fazer cast de `uint8_t*` para struct.** Ler `(struct cabecalho *)p` parece elegante,
  mas quebra em duas coisas: *alinhamento* (o pacote pode começar em endereço ímpar) e
  *strict aliasing* (o compilador pode assumir que ponteiros de tipos diferentes não se cruzam e
  otimizar errado). O UBSan dos testes pega parte disso. Ler byte a byte ou com `memcpy` é o jeito seguro.
- **Nunca confie no pacote.** Todo campo de tamanho pode mentir. Antes de ler `p[i]`, garanta
  `i < n`. A ordem das conferências importa: primeiro "tenho bytes suficientes para ler o campo
  de tamanho?", depois "o tamanho que ele diz cabe no buffer?".
- **Complemento de um.** O checksum soma palavras de 16 bits num acumulador de 32 bits, "dobra" o
  que passou de 16 bits de volta (`soma = (soma & 0xffff) + (soma >> 16)`, repetindo enquanto
  sobrar) e no fim inverte os bits (`~`). Por isso um cabeçalho com o checksum certo soma 0.
- **Fragmentação.** IPv4 marca fragmento pelo bit MF (byte 6, bit `0x20`) ou pelo Fragment Offset
  (13 bits: resto do byte 6 + byte 7) diferente de zero. IPv6 usa a extensão 44. A v1 só recusa.

## Armadilhas comuns

- `p[0] >> 4` é a versão; `p[0] & 0x0f` é o IHL, em palavras de 4 bytes (IHL 5 = 20 bytes).
- Com `-Wconversion` ligado, atribuir `int` a `uint16_t` sem cast dá erro de compilação. É de
  propósito: obriga você a pensar se o valor cabe.
- No IPv6, o laço das extensões precisa de limite (o contrato diz 8). Sem limite, um pacote
  malicioso com extensões apontando umas para as outras te prende ou te faz ler longe.
- Zere `out->origem`/`out->destino` no IPv4: o teste confere que os 12 bytes de sobra são zero.

## Quando terminar

Me chama: eu reviso o seu `.c` (corretude, memória e estilo) e explico o que eu mudaria e por quê.
Depois vem a Tarefa 2 (UDP, TCP e montar pacotes).

Se travar mais de uns 20 minutos num teste, me pede uma dica. Dou a ideia, não o código.
