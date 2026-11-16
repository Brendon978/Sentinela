# Aula 1 — Bits, bytes e números

Tudo o que passa pela rede é uma fila de bytes. Para ler um pacote, você precisa enxergar esses
bytes como o computador enxerga. Esta aula é a base de todas as outras.

---

## 1. Binário: contar só com 0 e 1

No decimal, cada casa vale 10 vezes a da direita: unidades, dezenas, centenas.

```
  3   4   7      =  3×100 + 4×10 + 7×1  = 347
 100  10   1
```

No **binário**, cada casa vale **2 vezes** a da direita, e só existem os dígitos 0 e 1. Cada
dígito binário é um **bit**.

```
  1   0   1   1      =  1×8 + 0×4 + 1×2 + 1×1  = 11
  8   4   2   1
```

Os valores das casas são as potências de 2. Vale decorar até 128:

| casa | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
|---|---|---|---|---|---|---|---|---|
| vale | 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |

### Binário → decimal

Some os valores das casas que têm 1.

`0110 0101` → casas 6, 5, 2 e 0 → 64 + 32 + 4 + 1 = **101**

### Decimal → binário

Vá tirando a maior potência de 2 que cabe.

**200** → cabe 128 (sobra 72) → cabe 64 (sobra 8) → 32 não cabe → 16 não cabe → cabe 8 (sobra 0)
→ casas 7, 6 e 3 → `1100 1000`

> Os espaços a cada 4 bits são só para ler melhor, como o ponto em 1.000.000.

---

## 2. Bit, byte e companhia

| nome | bits | maior valor sem sinal | tipo em C | tipo em C# |
|---|---|---|---|---|
| bit | 1 | 1 | — | `bool` (mais ou menos) |
| nibble | 4 | 15 | — | — |
| **byte** | 8 | 255 | `uint8_t` | `byte` |
| — | 16 | 65.535 | `uint16_t` | `ushort` |
| — | 32 | 4.294.967.295 | `uint32_t` | `uint` |
| — | 64 | ~1,8 × 10¹⁹ | `uint64_t` | `ulong` |

A regra: com **n** bits cabem **2ⁿ** valores, de 0 até 2ⁿ − 1. Com 8 bits: 2⁸ = 256 valores, de 0 a 255.

Na rede: uma porta TCP tem 16 bits (por isso vai até 65.535), um endereço IPv4 tem 32 bits e um
IPv6 tem 128 bits.

---

## 3. Hexadecimal: binário para humanos

Escrever 32 zeros e uns é ilegível. O **hexadecimal** (base 16) resolve isso: cada dígito hex
representa **exatamente 4 bits**. Os dígitos vão de 0 a 9 e depois A a F.

| hex | binário | decimal | | hex | binário | decimal |
|---|---|---|---|---|---|---|
| 0 | 0000 | 0 | | 8 | 1000 | 8 |
| 1 | 0001 | 1 | | 9 | 1001 | 9 |
| 2 | 0010 | 2 | | A | 1010 | 10 |
| 3 | 0011 | 3 | | B | 1011 | 11 |
| 4 | 0100 | 4 | | C | 1100 | 12 |
| 5 | 0101 | 5 | | D | 1101 | 13 |
| 6 | 0110 | 6 | | E | 1110 | 14 |
| 7 | 0111 | 7 | | F | 1111 | 15 |

Então **um byte = dois dígitos hex**. Em C (e em C#), número hex começa com `0x`.

`0x45` → `4` = `0100`, `5` = `0101` → `0100 0101` → 64 + 4 + 1 = **69**

`1100 1000` → `1100` = C, `1000` = 8 → **0xC8**

Para hex → decimal direto: cada casa vale 16 vezes a da direita.
`0x1E` = 1×16 + 14 = **30**. `0x5C2A` = 5×4096 + 12×256 + 2×16 + 10 = **23.594**.

> É por isso que o Wireshark mostra os pacotes em hex: cada par de dígitos é um byte.

---

## 4. Operações bit a bit

Elas trabalham bit por bit, casa por casa. São as mesmas em C e C#.

### AND (`&`): "os dois são 1?"

```
  1100 1010
& 0000 1111
  ---------
  0000 1010
```

Uso típico: **pegar só alguns bits** (máscara). `x & 0x0F` fica só com os 4 bits de baixo.

### OR (`|`): "algum é 1?"

```
  1100 0000
| 0000 0101
  ---------
  1100 0101
```

Uso típico: **ligar bits** ou **juntar pedaços**.

### XOR (`^`): "são diferentes?"

```
  1100 1010
^ 1111 0000
  ---------
  0011 1010
```

Uso típico: inverter bits escolhidos; aparece muito em criptografia.

### NOT (`~`): inverte tudo

`~ 1100 1010` = `0011 0101`

### Deslocamento (`<<` e `>>`)

Empurra os bits para a esquerda ou para a direita; o que sai some, e entra zero.

```
0000 0101 << 2  =  0001 0100      (5 vira 20: cada casa para a esquerda multiplica por 2)
1100 1000 >> 4  =  0000 1100      (200 vira 12: cada casa para a direita divide por 2)
```

### Receitas com máscara

| quero | código | exemplo com `x = 0100 0101` |
|---|---|---|
| testar o bit 2 | `(x >> 2) & 1` ou `x & 0x04` | dá 1 (ou 0x04): está ligado |
| ligar o bit 1 | `x \| 0x02` | `0100 0111` |
| desligar o bit 0 | `x & ~0x01` | `0100 0100` |
| 4 bits de cima | `x >> 4` | `0100` = 4 |
| 4 bits de baixo | `x & 0x0F` | `0101` = 5 |

Essas duas últimas linhas são, literalmente, como se lê a versão e o tamanho do cabeçalho IPv4:
o primeiro byte `0x45` diz **versão 4** (bits de cima) e **IHL 5** (bits de baixo).

### Juntar dois bytes num número de 16 bits

```
(0x12 << 8) | 0x34
 0001 0010 0000 0000      0x12 empurrado 8 casas
|          0011 0100      0x34
 -------------------
 0001 0010 0011 0100  =  0x1234
```

É exatamente o que o seu `checksum.c` faz em cada par de bytes.

---

## 5. Estouro e "vai um"

Um `uint8_t` vai até 255. E 255 + 1?

```
  1111 1111     (255)
+ 0000 0001
  ---------
1 0000 0000     o 1 da frente não cabe em 8 bits e é perdido → resultado 0
```

Com tipo **sem sinal**, o valor "dá a volta" (é aritmética módulo 2ⁿ). Isso é um bug clássico de
segurança: um tamanho que estoura e vira um número pequeno pode fazer o programa alocar pouca
memória e depois escrever demais.

No checksum, em vez de perder o "vai um", a gente o **guarda** usando 32 bits e depois soma de
volta embaixo (a "dobra"). Isso é o **complemento de um**:

```
soma = 0x1_4263                       passou de 16 bits
dobra: 0x4263 + 0x1 = 0x4264          o que vazou volta somado embaixo
inverte: ~0x4264 = 0xBD9B             checksum final
```

---

## 6. Números negativos: complemento de dois

Com sinal, o bit mais alto indica o sinal. Para achar o negativo de um número: **inverte todos os
bits e soma 1**.

```
 5 = 0000 0101
~5 = 1111 1010
+1 = 1111 1011  = -5 em 8 bits
```

Por isso `int8_t` vai de −128 a 127. Um mesmo byte `1111 1011` vale 251 se for `uint8_t` e −5
se for `int8_t`: **o tipo diz como interpretar os bits**. Em rede quase tudo é sem sinal.

> **Complemento de um** (só inverter) é outra coisa: é o que o checksum da Internet usa.

---

## 7. Ordem dos bytes (endianness)

Um número de 16 bits ocupa 2 bytes. Em que ordem eles vão para a memória ou para o cabo?

- **Big-endian:** o byte mais significativo primeiro. `0x1234` → `12 34`.
  É a **ordem da rede**: todos os cabeçalhos de protocolo usam.
- **Little-endian:** o menos significativo primeiro. `0x1234` → `34 12`.
  É como o seu PC (x86) e o seu celular (ARM) guardam números na memória.

Por isso não dá para "copiar" 2 bytes do pacote direto para uma variável: o PC leria `0x3412`.
O jeito seguro é montar byte a byte, como você fez: `(p[0] << 8) | p[1]`.

Exemplo real: no pacote de teste `v4_udp_simples`, os bytes 2 e 3 são `00 1e`. Em big-endian isso
é `0x001E` = **30**, o tamanho total do pacote. O Wireshark mostra exatamente "Total Length: 30".

---

## Exercícios

Faça sem calculadora; depois confira com o modo Programador.

1. Converta para decimal: `1010 1010`, `0001 0000`, `1111 1111`.
2. Converta para binário: 13, 64, 250.
3. Converta para hex: `1011 1110`, `0011 1100`; e para decimal: `0xFF`, `0x80`, `0x01BB`.
4. Calcule: `0xF0 & 0x3C`, `0xF0 | 0x0F`, `0xAA ^ 0xFF`, `0x01 << 7`, `0x80 >> 3`.
5. O primeiro byte de um pacote é `0x46`. Qual é a versão e o IHL? Quantos bytes tem o cabeçalho
   (IHL × 4)?
6. Os bytes `01 bb` são uma porta em big-endian. Que porta é? Que serviço costuma usar ela?
7. Some em 16 bits com complemento de um (dobre o vai um): `0xFFFF + 0x0002`.
8. Quanto vale o byte `1000 0000` como `uint8_t`? E como `int8_t`?

### Respostas

1. 170, 16, 255.
2. `1101`, `0100 0000`, `1111 1010`.
3. `0xBE`, `0x3C`; 255, 128, 443.
4. `0x30`, `0xFF`, `0x55`, `0x80`, `0x10`.
5. Versão 4 (`0x46 >> 4`), IHL 6 (`0x46 & 0x0F`), 24 bytes (tem 4 bytes de opções).
6. `0x01BB` = 443: HTTPS.
7. `0xFFFF + 0x0002` = `0x1_0001` → dobra: `0x0001 + 0x1` = **`0x0002`**.
8. 128 como `uint8_t`; −128 como `int8_t`.

## Para pesquisar mais

- CS50, aula 0 (binário, ASCII) — gratuito, com legenda.
- Charles Petzold, *Código: a linguagem oculta do hardware e do software*.
- RFC 1071, "Computing the Internet Checksum" — curta, com código de exemplo.
