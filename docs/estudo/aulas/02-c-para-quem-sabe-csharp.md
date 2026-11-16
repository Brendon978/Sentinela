# Aula 2 — C para quem já sabe C#

O C# herdou a sintaxe do C: `if`, `for`, `while`, `switch`, chaves, ponto e vírgula, operadores.
O que muda é **quem cuida da memória**. No C# o runtime cuida, e no C quem cuida é você. Esta aula
foca nessa diferença.

---

## 1. Do código ao executável

C# compila para IL e roda numa máquina virtual (.NET). C compila **direto para código de máquina**.

```
ola.c ──(compilador)──► ola.o ──(linker)──► ola  (executável)
```

```c
/* ola.c */
#include <stdio.h>

int main(void) {
    printf("ola, %s! %d + %d = %d\n", "Brendon", 2, 3, 2 + 3);
    return 0;
}
```

```sh
clang -Wall -Wextra -o ola ola.c   # compila (os -W ligam avisos: use sempre)
./ola                              # roda
```

- `main` é o ponto de entrada; devolve 0 quando deu tudo certo.
- `#include <stdio.h>` é como um `using`, mas literal: o pré-processador **cola o conteúdo** do
  arquivo ali.
- `printf` usa marcadores: `%d` inteiro, `%u` sem sinal, `%x` hex, `%s` string, `%zu` `size_t`,
  `%p` ponteiro.

---

## 2. Tipos

Em C, `int` e `long` mudam de tamanho conforme a máquina. Para rede, onde o tamanho importa,
usamos os tipos de **tamanho fixo** de `<stdint.h>`:

| C | C# | |
|---|---|---|
| `uint8_t` / `int8_t` | `byte` / `sbyte` | 8 bits |
| `uint16_t` / `int16_t` | `ushort` / `short` | 16 bits |
| `uint32_t` / `int32_t` | `uint` / `int` | 32 bits |
| `uint64_t` / `int64_t` | `ulong` / `long` | 64 bits |
| `size_t` | (tipo de tamanhos e índices) | 64 bits no PC e no celular |
| `char` | (1 byte, não é o `char` de 16 bits do C#) | 8 bits |
| `_Bool` / `bool` (`<stdbool.h>`) | `bool` | |

**Conversões silenciosas.** C converte tipos sem avisar: `uint8_t x = 300;` vira 44 (300 − 256).
Por isso o projeto compila com `-Wconversion`, que faz o compilador reclamar e te obriga a
escrever o cast `(uint8_t)` quando é de propósito.

**Promoção para int.** Em contas, tipos menores que `int` viram `int` primeiro. `p[i] << 8` com
`p[i]` sendo `uint8_t` dá um `int`. É por isso que aparecem casts como `(uint32_t)(...)`.

---

## 3. Ponteiros — o assunto principal

A memória é um vetorzão de bytes, cada um com um **endereço** (um número). Um **ponteiro** é uma
variável que guarda um endereço.

```c
int x = 42;
int *p = &x;     /* p guarda o endereço de x.   & = "endereço de"   */
printf("%d\n", *p);  /* 42.                      * = "o que está no endereço" */
*p = 7;          /* muda x através de p: agora x vale 7 */
```

```
memória:   endereço 1000: [ 42 ]  ← x
           endereço 2000: [1000]  ← p (aponta para x)
```

Em C# você já usa isso sem ver: toda variável de classe é uma referência (um ponteiro com regras).
O `ref` e o `out` também são ponteiros. Em C, o ponteiro é explícito e **não tem regras**: ele
pode apontar para qualquer lugar, inclusive para lixo.

### Ponteiro para mudar um valor fora da função

C não tem `out`. Usa-se ponteiro:

```c
void dobra(int *v) { *v = *v * 2; }

int n = 5;
dobra(&n);   /* n agora é 10 */
```

É assim que `sn_ip_ler(p, n, &ip)` preenche a struct `ip`.

### NULL

`NULL` é o ponteiro "para nada", como o `null` do C#. Ler `*p` com `p == NULL` derruba o programa
(*segmentation fault*), só que sem `NullReferenceException` bonitinha.

---

## 4. Arrays: sem `.Length`

```c
uint8_t pacote[4] = {0x45, 0x00, 0x00, 0x1e};
pacote[0];      /* 0x45 */
```

Quando você passa um array para uma função, passa **só o endereço do primeiro elemento**. O
tamanho se perde. Por isso as funções em C recebem sempre o par **ponteiro + tamanho**:

```c
uint16_t sn_checksum(const uint8_t *p, size_t n, uint32_t soma_inicial);
```

`p[i]` é só um atalho para `*(p + i)`: "ande i elementos a partir de p e leia". **Nada impede
`p[n + 10]`**. O C lê o que estiver lá, e isso se chama **estouro de buffer** (*buffer overflow*),
a vulnerabilidade mais famosa da história. Toda vez que você indexa, a pergunta é: **"tenho
certeza de que esse índice é menor que o tamanho?"**

`const` na frente (`const uint8_t *p`) promete que a função só lê.

---

## 5. Strings

Em C não existe tipo string. Uma string é um array de `char` que termina com o byte `0` (`'\0'`):

```c
char nome[] = "Sentinela";   /* 10 bytes: 9 letras + o '\0' */
strlen(nome);                /* 9: conta até achar o '\0' */
```

Se faltar o `'\0'`, `strlen` e `printf` continuam lendo memória até achar um zero por acaso.
Funções perigosas: `strcpy`, `strcat`, `sprintf`, `gets` (não sabem o tamanho do destino). Use
`snprintf(dest, sizeof dest, ...)`, que respeita o tamanho.

Nomes de domínio que vêm de um pacote **não** têm `'\0'`: eles vêm com o tamanho na frente. Nunca
trate dado da rede como string sem conferir.

---

## 6. struct, enum, typedef

```c
typedef struct {
    uint8_t versao;
    uint8_t protocolo;
    uint16_t tam_total;
} sn_ip;               /* typedef dá um nome curto para o tipo */

sn_ip ip;              /* na pilha, sem new */
ip.versao = 4;

sn_ip *pi = &ip;
pi->versao = 6;        /* -> é o . quando você tem um ponteiro */
```

`struct` em C é como uma `struct` do C#: só dados, sem métodos, sem herança. As "funções da
classe" viram funções soltas que recebem um ponteiro para a struct, como `sn_ip_ler(..., sn_ip *out)`.

`enum` dá nomes a números, como os códigos de erro `SN_ERR_CURTO = -1`.

---

## 7. Memória: pilha e heap

| | pilha (stack) | heap |
|---|---|---|
| como cria | `uint8_t buf[64];` | `uint8_t *buf = malloc(64);` |
| quando some | sozinha, no fim da função | **só quando você chama `free(buf)`** |
| tamanho | pequeno e fixo | grande, decidido em tempo de execução |
| C# parecido | variável local de `struct` | `new` (mas lá o GC libera para você) |

Os três erros clássicos com heap:

1. **Vazamento:** esquecer o `free`. A memória fica presa até o programa acabar.
2. **Uso depois de liberar** (*use-after-free*): usar o ponteiro depois do `free`. Lê lixo ou o
   dado de outra coisa — é falha de segurança séria.
3. **Liberar duas vezes** (*double free*): corrompe o gerenciador de memória.

E um da pilha: **devolver o endereço de uma variável local**. Ela some quando a função termina, e
o ponteiro passa a apontar para lixo.

`malloc` pode devolver `NULL` se faltar memória: confira sempre.

---

## 8. Comportamento indefinido (UB)

Em C#, erro vira exceção. Em C, várias coisas são **comportamento indefinido**: o padrão da
linguagem diz que *qualquer coisa* pode acontecer, e o compilador pode até otimizar o código
assumindo que aquilo nunca ocorre. Exemplos:

- ler ou escrever fora de um array;
- usar variável sem inicializar;
- estouro de inteiro **com sinal** (`int` passando do máximo);
- deslocar mais bits do que o tipo tem (`x << 40` num `uint32_t`);
- ler um `uint8_t*` como se fosse `uint32_t*` desalinhado.

O programa pode "funcionar" no seu PC e quebrar no celular. Por isso os testes do Sentinela rodam
com **AddressSanitizer** (pega acesso fora da memória, uso depois de liberar, vazamento) e
**UndefinedBehaviorSanitizer** (pega UB como estouro com sinal e deslocamento inválido).

---

## 9. Header (.h) e implementação (.c)

- O `.h` tem as **declarações**: tipos, constantes e assinaturas. É o contrato, como uma
  `interface` do C#.
- O `.c` tem o **corpo** das funções.
- Quem quer usar inclui o `.h`. O linker junta tudo no final.

```c
/* sn_ip.h */
#ifndef SN_IP_H        /* "guarda de inclusão": evita colar o arquivo duas vezes */
#define SN_IP_H
int sn_ip_ler(const uint8_t *p, size_t n, sn_ip *out);
#endif
```

Funções `static` num `.c` são privadas daquele arquivo (como `private`).

---

## 10. Ferramentas do dia a dia

| ferramenta | para quê |
|---|---|
| `clang` / `gcc` | compilar |
| `cmake` + `ninja` | organizar a compilação de muitos arquivos (como o `.csproj`) |
| `gdb` (ou `lldb`) | depurador: pausar, olhar variáveis, andar linha a linha |
| `-fsanitize=address,undefined` | os sanitizers |
| `valgrind` | outro detector de erros de memória |

Comandinho do gdb para começar: `gdb ./testes`, depois `break sn_ip_ler`, `run ip`, `next`,
`print *out`, `bt` (mostra a pilha de chamadas).

---

## Exercícios

1. Escreva um `main` que declara `uint8_t b[] = {0x12, 0x34, 0x56};` e imprime cada byte com
   `printf("%02x ", b[i]);` usando `sizeof b` para saber o tamanho. Por que `sizeof b` funciona
   aqui, mas não funcionaria dentro de uma função que recebeu `b` como parâmetro?
2. Escreva `void troca(int *a, int *b)` que troca os valores de duas variáveis.
3. Este código tem um bug. Qual?
   ```c
   int soma(const uint8_t *p, size_t n) {
       int s = 0;
       for (size_t i = 0; i <= n; i++) s += p[i];
       return s;
   }
   ```
4. E este?
   ```c
   char *nome(void) {
       char buf[16];
       snprintf(buf, sizeof buf, "sentinela");
       return buf;
   }
   ```
5. Quanto vale `uint8_t x = 200; x = x + 100;`? E por que o compilador do projeto reclamaria?
6. O que imprime: `int a = 5; int *p = &a; *p += 1; printf("%d", a);`?

### Respostas

1. `sizeof b` dá 3 porque, ali, `b` é o array mesmo. Dentro de uma função, o parâmetro vira um
   ponteiro e `sizeof` daria o tamanho do ponteiro (8). Por isso as funções recebem o tamanho à parte.
2. `void troca(int *a, int *b) { int t = *a; *a = *b; *b = t; }`, chamada como `troca(&x, &y);`
3. `i <= n` lê `p[n]`, um byte depois do fim. O certo é `i < n`. (O AddressSanitizer pega.)
4. Devolve o endereço de `buf`, que é local e some quando a função termina. Soluções: receber o
   buffer de quem chama (`void nome(char *dest, size_t cap)`) ou usar `malloc` (e alguém dá `free`).
5. 300 não cabe em 8 bits: vira 44 (300 − 256). `x + 100` é calculado como `int` e voltar para
   `uint8_t` perde informação: o `-Wconversion` acusa e pede o cast explícito.
6. `6`.

## Para pesquisar mais

- **CS50** (Harvard), semanas 1 a 5: C, arrays, memória, ponteiros. Gratuito, com legenda.
- K. N. King, *C Programming: A Modern Approach* — o melhor livro para aprender C de verdade.
- Beej's Guide to C Programming (beej.us/guide/bgc) — gratuito.
- "Smashing the Stack for Fun and Profit" (Aleph One, 1996) — o texto clássico sobre estouro de
  buffer, para quando quiser ver o lado do ataque.
