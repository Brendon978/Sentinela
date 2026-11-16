# Sentinela v1 — plano de implementação

## Objetivo

App Android pessoal (Galaxy S25 FE, Android 16, sem root) que captura o tráfego de rede do próprio
celular por uma VPN local, mostra qual app gerou cada conexão e guarda cada captura como evidência
(`.pcap` + SHA-256). Projeto de estudo: o miolo de pacotes é escrito em C pelo Brendon, e a casca
(Kotlin/Compose, VPN, banco, telas) pelo Claude.

## Fonte dos requisitos

Entrevista de 2026-11-12 (memória `sentinela-app.md`). Decisões do usuário:

| # | Requisito | Fonte |
|---|---|---|
| R1 | Objetivo é aprender e montar portfólio; partes difíceis escritas à mão, sem biblioteca pronta de pilha TCP/IP | resposta "Aprender e portfólio" |
| R2 | Divisão mista: Claude faz a casca; Brendon escreve o miolo de pacotes em **C** pelo NDK, com roteiro | respostas "Misto" e "C" |
| R3 | Captura só por sessão (gravar/parar); fora dela o Tailscale funciona | resposta "Liga a captura só na hora" |
| R4 | IPv4 e IPv6 na v1 | resposta "Sim, IPv4 e IPv6" |
| R5 | Lista ao vivo de conexões: app, domínio, IP, porta, protocolo, bytes | telas v1 |
| R6 | Detalhe do pacote por camadas, como no Wireshark | telas v1 |
| R7 | Resumo por app com rastreadores conhecidos | telas v1 |
| R8 | Alertas por regras fixas: madrugada/tela desligada, domínio nunca visto, rastreador, porta incomum, DNS escondido (DoT/DoH) | resposta "Regras fixas simples" |
| R9 | Sessões salvas: `.pcap` + resumo em SQLite + SHA-256 + horário, reabríveis | resposta "Sessões salvas" |
| R10 | Repo novo em `~/brendon projects/sentinela`, GitHub Brendon978 via host `github-pessoal` | resposta "Repo novo próprio"; memória `contas-git-pessoal-trabalho` |
| R11 | Nunca usar serviço de acessibilidade nem sobreposição de tela | memória `menu-launcher` (Nubank) |
| R12 | Nada no celular (install, run, print) sem o OK do Brendon na hora | memória `menu-launcher` / `build-garage-jogo` |

Fora da v1: mapa da rede local (fase 2), sensor externo (fase 3), linha de base por app, abrir HTTPS,
ICMP (ping) e SNI de QUIC.

## Mudança de divisão (2026-11-13)

O Brendon pediu: o **Claude escreve o app do celular inteiro, inclusive o C**, e o Brendon estuda
em paralelo pelo material em `docs/estudo/` (roteiro + 11 aulas). Ele ajuda depois na parte do PC
(sensor/laboratório). As marcações **[C — Brendon]** abaixo passam a ser **[C — Claude]**, mantendo
testes e oráculo do tshark; o código C deve vir bem comentado, porque também é material de estudo.
O exercício que ele começou está em `docs/estudo/exercicios/checksum-do-brendon.c`.

## Como o trabalho era dividido (modelo de estudo original)

Em cada tarefa marcada **[C — Brendon]**:

1. O Claude escreve o **header** (`.h`, o contrato), os **testes** e o roteiro da tarefa (conceitos,
   leitura e armadilhas).
2. O Brendon roda os testes, vê falhar e escreve o `.c` até passarem. Pode pedir dica, mas o código é dele.
3. O Claude revisa o `.c` (corretude, memória, estilo C) e explica o que achar.

Testes C rodam **no PC**, sem celular, com AddressSanitizer + UndefinedBehaviorSanitizer:
`tools/testes-c.sh [filtro]`. O oráculo dos testes é independente do nosso código: pacotes montados
com **scapy** e conferidos pelo **tshark** (Wireshark), nunca valores recalculados pelo próprio parser.

Tarefas **[Kotlin — Claude]** seguem TDD normal, com testes JVM (`./gradlew testDebugUnitTest --tests ...`).

## Arquitetura

```
┌──────────────── app (Kotlin/Compose) ─────────────────┐
│ Telas: Sessões · Ao vivo · Conexão/Pacote · Por app · Alertas
│ SessaoService (VpnService, primeiro plano)             │
│   ├─ Builder: 10.111.0.1/32 + fd00:5e:1::1/128,        │
│   │   rotas 0.0.0.0/0 e ::/0, DNS virtual 10.111.0.53  │
│   │   e fd00:5e:1::53, addDisallowedApplication(self)  │
│   ├─ DonoDaConexao: getConnectionOwnerUid → pacote     │
│   ├─ Alertas (Kotlin puro) · Rastreadores              │
│   └─ Banco (Room/SQLite) · SHA-256 · exportação (SAF)  │
│        ▲ eventos (lote binário a cada 250 ms)          │
├────────┼──────────── JNI (libsentinela.so) ────────────┤
│ motor.c: laço poll() sobre o fd do tun + sockets reais │
│   ip.c/udp.c/tcp.c (parse e montagem) · checksum.c     │
│   fluxos.c (tabela 5-tupla) · relay_udp.c · relay_tcp.c│
│   dns.c (nomes ↔ IPs) · sni.c (TLS ClientHello)        │
│   pcap.c (escrita e leitura) · dissecar.c (camadas)    │
│   eventos.c (fila para o Kotlin)                       │
└────────────────────────────────────────────────────────┘
```

- **Reencaminhamento (NAT em espaço de usuário):** o tun entrega pacotes IP crus dos apps. Para cada
  fluxo o motor abre um socket real (o próprio app está fora da VPN por `addDisallowedApplication`,
  então seus sockets não voltam ao tun) e devolve as respostas montando pacotes IP no tun.
  UDP é relé direto. TCP é **terminado** no motor: ele faz o handshake com o app, mantém seq/ack e
  janela, e repassa o fluxo de bytes pelo socket real.
- **DNS:** pacotes para o DNS virtual vão para os servidores DNS da rede ativa (lidos pelo Kotlin em
  `LinkProperties` e passados ao motor). O motor lê as respostas para ligar IP → domínio.
- **Domínio de cada conexão:** SNI do ClientHello (TCP 443) quando houver; senão, o último nome que
  resolveu para aquele IP; senão, só o IP.
- **QUIC (UDP 443):** passa normalmente e mostra domínio só pelo DNS. Há uma opção "Forçar TCP"
  (desligada por padrão) que descarta UDP 443 para os apps caírem em TCP e o SNI aparecer.
- **Captura:** todo pacote que passa pelo tun (nos dois sentidos) vai para o `.pcap` da sessão,
  formato pcap clássico com `LINKTYPE_RAW` (101), carimbo em microssegundos.
- **Evidência:** ao parar, o Kotlin fecha o `.pcap`, calcula o SHA-256, grava na sessão e gera junto
  um `sessao.sha256` no formato do `sha256sum`.

## Contratos entre tarefas

### C1 — API C do motor (`native/include/sentinela.h`, Tarefa 8)

> **Revisto na Tarefa 6 (2026-11-16):** `sn_motor_criar` recebe uma `sn_config` (pcap, DNS
> virtuais, DNS reais com porta, forçar TCP e relógio injetável) em vez de parâmetros soltos, e
> ganhou `sn_motor_encerrar` (emite os eventos finais antes de liberar). O header é a fonte da verdade.

```c
typedef struct sn_motor sn_motor;
sn_motor *sn_motor_criar(const char *caminho_pcap, const char *const *dns, int n_dns, int forcar_tcp);
int       sn_motor_rodar(sn_motor *m, int fd_tun);   /* bloqueia até sn_motor_parar; 0 = ok */
void      sn_motor_parar(sn_motor *m);               /* qualquer thread; acorda o poll por eventfd */
size_t    sn_motor_eventos(sn_motor *m, uint8_t *buf, size_t cap); /* drena a fila; bytes escritos */
void      sn_motor_destruir(sn_motor *m);            /* fecha pcap, sockets e o fd do tun */
```
Invariantes: o motor é dono do `fd_tun` (fecha no destruir); `sn_motor_eventos` é a única função
chamada de outra thread além de `sn_motor_parar`; nenhum evento se perde (fila cresce até 4 MiB, e
acima disso o motor conta `eventos_descartados` e emite `EV_PERDA`).

### C2 — Formato dos eventos (C → Kotlin, Tarefa 8)

Registros concatenados, little-endian: `u8 tipo | u16 tamanho_do_corpo | corpo`.

| tipo | nome | corpo |
|---|---|---|
| 1 | `EV_FLUXO_NOVO` | `u32 id, u8 versao_ip(4/6), u8 proto(6/17), u8[16] ip_origem, u16 porta_origem, u8[16] ip_destino, u16 porta_destino, u64 inicio_us` (IPv4 nos 4 primeiros bytes, resto zero) |
| 2 | `EV_FLUXO_BYTES` | `u32 id, u64 bytes_enviados, u64 bytes_recebidos, u32 pacotes` (totais acumulados) |
| 3 | `EV_FLUXO_FIM` | `u32 id, u64 fim_us, u8 motivo` (0 fechado, 1 reset, 2 tempo esgotado, 3 erro de conexão) |
| 4 | `EV_DNS` | `u16 n_ips, u8 versao[n], u8[16] ip[n], u16 tam_nome, nome` (UTF-8, sem `\0`) |
| 5 | `EV_SNI` | `u32 id, u16 tam_nome, nome` |
| 6 | `EV_PERDA` | `u32 eventos_descartados` |

O Kotlin ignora tipos desconhecidos pulando `tamanho_do_corpo` (para evoluir sem quebrar).

### C3 — JNI (`app/.../motor/Motor.kt` ↔ `native/src/jni.c`, Tarefa 8)

```kotlin
object Motor {
    external fun criar(caminhoPcap: String, dns: Array<String>, forcarTcp: Boolean): Long
    external fun rodar(handle: Long, fdTun: Int): Int   // chamado numa thread própria
    external fun parar(handle: Long)
    external fun eventos(handle: Long): ByteArray
    external fun destruir(handle: Long)
    external fun dissecar(pacote: ByteArray): String   // árvore em texto, Tarefa 12
    external fun lerPacotes(caminhoPcap: String, fluxo: ChaveFluxo, max: Int): Array<ByteArray> // Tarefa 12
}
```
O `fdTun` vem de `ParcelFileDescriptor.detachFd()`: a partir daí só o motor fecha.

### C4 — Banco (Room, Tarefa 10)

- `sessao(id, inicio_ms, fim_ms?, caminho_pcap, sha256?, pacotes, bytes, eventos_perdidos)`
- `fluxo(sessao_id, fluxo_id, proto, versao_ip, ip_origem, porta_origem, ip_destino, porta_destino, uid, pacote_app?, dominio?, origem_dominio(SNI|DNS|NENHUM), bytes_env, bytes_rec, pacotes, inicio_us, fim_us?, motivo_fim?)`, chave `(sessao_id, fluxo_id)`
- `dominio_visto(pacote_app, dominio, primeira_vez_ms)` — memória para "domínio nunca visto"
- `alerta(id, sessao_id, fluxo_id, regra, pacote_app, detalhe, quando_ms)`

## Tarefas

Legenda: **[C — Brendon]**, **[Kotlin — Claude]**, **[Infra — Claude]**. ⚠ = tarefa de base ou
risco, com revisão própria (motivo ao lado).

### Tarefa 0 — Ambiente e repositório [Infra — Claude] ⚠ base: tudo depende do build

- `git init` em `~/brendon projects/sentinela`, remote `git@github-pessoal:Brendon978/sentinela.git`
  (repo criado pelo Brendon no GitHub; push só com o OK dele).
- Instalar NDK `30.0.16248370` e o CMake do SDK por `sdkmanager`.
- **Pedido ao Brendon** (precisa de sudo): `sudo pacman -S wireshark-cli tcpdump`; scapy num venv do
  projeto (`tools/.venv`, `pip install scapy`).
- Projeto Gradle copiando as versões do `meu-launcher` (AGP 9.5.0, Kotlin 2.4.21, Compose BOM
  2026.09.00, compileSdk/targetSdk 37, minSdk 35, Java 17), pacote `com.brendon978.sentinela`, só
  `arm64-v8a`, `externalNativeBuild` com `native/CMakeLists.txt`.
- `native/CMakeLists.txt` com dois alvos: `sentinela` (shared, Android) e `testes` (executável no
  host com `-fsanitize=address,undefined -Wall -Wextra -Werror -std=c17`).
- `native/tests/teste.h`: macros mínimas `TESTE(nome)`, `CONFERE(cond)`, `CONFERE_IGUAL_MEM(a,b,n)`
  e filtro por nome na linha de comando.
- `tools/testes-c.sh [filtro]` (configura, compila e roda), `tools/fixtures/gerar.py` (scapy → `.hex`)
  e `tools/fixtures/oraculo.sh` (tshark → JSON esperado).
- `README.md` com objetivo, aviso legal (só no próprio aparelho/rede) e como rodar.

Prova: `tools/testes-c.sh` → `1 teste, 0 falhas` (teste de fumaça); `./gradlew assembleDebug` → APK
com `lib/arm64-v8a/libsentinela.so`; `tshark --version` responde.

### Tarefa 1 — Checksum e cabeçalhos IPv4/IPv6 [C — Brendon]

Arquivos: `native/include/sn_ip.h`, `native/src/checksum.c`, `native/src/ip.c`, `native/tests/t_ip.c`.

- `uint16_t sn_checksum(const uint8_t *p, size_t n, uint32_t soma_inicial)` (soma em complemento de um).
- `int sn_ip_ler(const uint8_t *p, size_t n, sn_ip *out)` → versão, tamanho do cabeçalho, protocolo,
  origem/destino, tamanho total, TTL/hop limit. IPv6: pula extensões Hop-by-Hop, Routing e
  Destination Options; **fragmento → `SN_ERR_FRAGMENTO`** (descartado na v1).
- Retornos negativos para: buffer curto, versão desconhecida, IHL < 5, tamanho total maior que o buffer.

Testes (fixtures do scapy, valores do tshark): IPv4 com e sem opções, IPv6 simples, IPv6 com Hop-by-Hop,
fragmento, pacote truncado em cada byte (nenhum acesso fora do buffer — o ASan prova), checksum de
cabeçalho real confere com o campo do pacote.

Roteiro: RFC 791 (§3.1), RFC 8200 (§3–4), RFC 1071 (checksum); ordem de bytes (`ntohs`), por que não
fazer cast de `uint8_t*` para struct (alinhamento e *strict aliasing*), `memcpy` para ler campos.

Prova: `tools/testes-c.sh ip` → todos passam, sem relato do ASan.

### Tarefa 2 — UDP, TCP e montagem de pacotes [C — Brendon]

Arquivos: `native/include/sn_transporte.h`, `native/src/udp.c`, `native/src/tcp.c`, `native/src/montar.c`, `native/tests/t_transporte.c`.

- Parse de UDP e TCP (portas, seq, ack, flags, janela, offset, opção MSS).
- Checksum com pseudo-cabeçalho IPv4 e IPv6.
- `sn_montar_udp(...)` e `sn_montar_tcp(...)`: escrevem num buffer um pacote IP completo (v4 ou v6)
  com checksums corretos — é o que o motor usa para responder ao app.

Testes: parse confere com o tshark; pacote montado é aceito pelo tshark sem `checksum bad`
(`tshark -o tcp.check_checksum:TRUE`) e reparseado igual; MSS presente e ausente; offset inválido.

Roteiro: RFC 768, RFC 9293 (§3.1 cabeçalho, §3.4 números de sequência), pseudo-cabeçalho de RFC 8200 §8.1.

Prova: `tools/testes-c.sh transporte` → todos passam.

### Tarefa 3 — Gravar e ler `.pcap` [C — Brendon]

Arquivos: `native/include/sn_pcap.h`, `native/src/pcap.c`, `native/tests/t_pcap.c`.

- Escrita: cabeçalho global (magic `0xa1b2c3d4`, versão 2.4, snaplen 65535, linktype 101) e registro
  por pacote (segundos, microssegundos, tamanho gravado, tamanho original). `fflush` a cada 1 s ou 256 pacotes.
- Leitura: iterar registros; filtrar pela 5-tupla de um fluxo (nos dois sentidos) até `max` pacotes.

Testes: arquivo gravado com 3 pacotes conhecidos → `capinfos` diz 3 pacotes, linktype Raw IP;
`tshark -r` reconhece os 3; leitura filtrada devolve só os do fluxo; arquivo truncado no meio de um
registro não estoura (devolve o que leu inteiro).

Roteiro: formato pcap (wiki do Wireshark "Development/LibpcapFileFormat"), E/S com `FILE*`, buffer e `fflush`.

Prova: `tools/testes-c.sh pcap` → todos passam.

### Tarefa 4 — DNS e SNI [C — Brendon] ⚠ risco: lê dado vindo da rede (entrada hostil)

Arquivos: `native/include/sn_nomes.h`, `native/src/dns.c`, `native/src/sni.c`, `native/tests/t_nomes.c`.

- DNS: ler pergunta e respostas A/AAAA de uma resposta UDP, com ponteiros de compressão; laço de
  ponteiros limitado (máx. 32 saltos), nome máx. 253 caracteres.
- SNI: do primeiro segmento TCP com payload, achar o ClientHello e a extensão `server_name` (tipo 0).
  ClientHello partido em mais de um segmento → "sem SNI" na v1.

Testes: respostas reais do scapy (com CNAME + A, com AAAA, com compressão); pacote com laço de
ponteiros; nome gigante; ClientHello real (bytes de um `openssl s_client` capturado) com e sem SNI;
cada fixture truncada byte a byte sem leitura fora do buffer.

Roteiro: RFC 1035 (§4.1, §4.1.4 compressão), RFC 8446 (§4.1.2) e RFC 6066 (§3); por que parser de
rede é onde moram as vulnerabilidades (exemplo: CVEs de parsers DNS).

Prova: `tools/testes-c.sh nomes` → todos passam.

### Tarefa 5 — Tabela de fluxos [C — Brendon]

Arquivos: `native/include/sn_fluxos.h`, `native/src/fluxos.c`, `native/tests/t_fluxos.c`.

- Tabela hash pela 5-tupla (versão, proto, ips, portas), id sequencial `u32`, busca nos dois sentidos.
- Expiração: UDP sem tráfego por 60 s; TCP fechado sai depois de 10 s; TCP ocioso por 2 h.
  O relógio é **injetado** (`uint64_t agora_us` em cada chamada), nunca lido dentro da tabela.
- Capacidade inicial 1024, cresce dobrando.

Testes: inserir/achar/remover; 10 000 fluxos com rehash; expiração com relógio falso nos limites
(59 s fica, 60 s sai); colisões.

Roteiro: hash de tupla (FNV-1a), endereçamento aberto ou encadeamento, `realloc` seguro.

Prova: `tools/testes-c.sh fluxos` → todos passam.

### Tarefa 6 — Motor com relé UDP e DNS [C — Brendon + harness Claude] ⚠ risco: concorrência e prazos

Arquivos: `native/src/motor.c`, `native/src/relay_udp.c`, `native/src/eventos.c` (Claude),
`native/tests/t_motor_udp.c`, `native/tests/tun_falso.c` (Claude).

- Laço `poll()` sobre o fd do tun, os sockets dos fluxos e um `eventfd` de parada.
- Pacote UDP do app → cria fluxo, abre socket UDP não bloqueante, envia o payload; resposta → monta
  pacote e escreve no tun. DNS virtual → troca o destino pelo servidor real.
- Grava no `.pcap` os pacotes nos dois sentidos e emite os eventos de C2.
- **Tun falso para teste:** `socketpair(AF_UNIX, SOCK_SEQPACKET)` preserva os limites de pacote como
  o tun. O teste faz o papel do app: manda um datagrama para um eco UDP local em `127.0.0.1` e em
  `::1`, e um "DNS" falso local responde.

Testes: eco UDP v4 e v6 com conteúdo e checksums certos; consulta ao DNS virtual responde e gera
`EV_DNS`; fluxo expira com relógio falso; `sn_motor_parar` de outra thread encerra o `rodar` em até 1 s
(teto generoso), e nenhuma thread fica viva no fim; pcap resultante abre no tshark sem erro.

Roteiro: `poll`, sockets não bloqueantes, `eventfd`, `sendto/recvfrom`, por que o relógio é injetado.

Prova: `tools/testes-c.sh motor_udp` → todos passam, sem relato do ASan/UBSan.

### Tarefa 7 — Relé TCP [C — Brendon] ⚠ risco: máquina de estados, prazos e a parte mais difícil

Arquivos: `native/src/relay_tcp.c`, `native/tests/t_motor_tcp.c`. Feita em fatias, cada uma com seu teste:

1. SYN do app → `connect` não bloqueante; conectou → SYN-ACK com MSS; falhou → RST.
2. Dados app → servidor: ACK correto, segmento duplicado (retransmissão do app) não reenvia.
3. Dados servidor → app: quebra em segmentos ≤ MSS do app e respeita a janela anunciada; janela 0 pausa a leitura do socket.
4. Fechamento: FIN do app → `shutdown(SHUT_WR)`; EOF do servidor → FIN para o app; meio-fechamento nos dois sentidos.
5. RST de qualquer lado encerra e emite `EV_FLUXO_FIM` com motivo 1.
6. SNI: primeiro payload passa pelo `sni.c` e emite `EV_SNI`.

Testes (tun falso + servidor TCP local v4 e v6): handshake; transferência de 1 MiB nos dois sentidos
com SHA-256 igual; janela 0 e reabertura; servidor recusa → RST; FIN dos dois lados; ClientHello gera `EV_SNI`.

Roteiro: RFC 9293 (§3.3.2 diagrama de estados, §3.8 janela), o que é terminar TCP num proxy, por que
o motor não precisa retransmitir para o app (o tun é local), mas precisa aceitar retransmissões dele.

Prova: `tools/testes-c.sh motor_tcp` → todos passam, sem relato do ASan/UBSan.

### Tarefa 8 — Ponte JNI e leitura de eventos [Kotlin+C — Claude] ⚠ contrato entre módulos e threads

Arquivos: `native/src/jni.c`, `app/src/main/java/com/brendon978/sentinela/motor/{Motor.kt,Eventos.kt}`, testes JVM.

- Implementa C1 e C3; `Eventos.kt` decodifica C2 em `sealed interface Evento`.
- Testes JVM do decodificador com bytes montados à mão a partir da tabela C2 (inclusive tipo
  desconhecido pulado e lote cortado no meio → erro claro, sem exceção não tratada).
- Teste C: `sn_motor_eventos` drenando de outra thread enquanto o motor emite (ASan + `-fsanitize=thread` num alvo separado).

Prova: `./gradlew testDebugUnitTest --tests '*Eventos*'` → passa; `tools/testes-c.sh eventos` → passa;
`./gradlew assembleDebug` → ok.

### Tarefa 9 — Serviço de VPN por sessão [Kotlin — Claude] ⚠ risco: serviço em primeiro plano e permissões

Arquivos: `app/.../vpn/SessaoService.kt`, `DonoDaConexao.kt`, `AndroidManifest.xml`.

- `VpnService.prepare()` na primeira vez (o Android mostra o aviso; quem confirma é o Brendon).
- Builder conforme a arquitetura; MTU 1500; `addDisallowedApplication(packageName)`.
- Serviço em primeiro plano com notificação "Gravando" e botão Parar. Tipo do serviço: conferir na
  documentação do Android 16 o tipo aceito para VPN (`systemExempted` ou `specialUse`) antes de fechar.
- DNS reais lidos de `ConnectivityManager.getLinkProperties(activeNetwork).dnsServers` antes de
  estabelecer a VPN. **DNS privado do sistema (DoT) ligado** pode desviar as consultas: a tela avisa
  quando `isPrivateDnsActive`.
- `DonoDaConexao`: no `EV_FLUXO_NOVO`, `getConnectionOwnerUid(proto, local, remoto)` → uid →
  `packageManager.getPackagesForUid` + rótulo. UID desconhecido (`-1`) fica "Sistema/desconhecido".
- Observa tela ligada/desligada (`ACTION_SCREEN_ON/OFF`) para a regra de alerta.
- Sem `BIND_ACCESSIBILITY_SERVICE` e sem `SYSTEM_ALERT_WINDOW`: teste de manifesto como no launcher (R11).

Prova: testes JVM de `DonoDaConexao` (com o `ConnectivityManager` como fronteira dublada) e do teste
de manifesto; **no aparelho, só com o OK do Brendon**: gravar 1 min abrindo 3 sites, parar, e o
Tailscale volta a conectar.

### Tarefa 10 — Sessões, banco, hash e exportação [Kotlin — Claude]

Arquivos: `app/.../dados/*` (Room), `app/.../sessao/Evidencia.kt`.

- Tabelas C4; o serviço grava fluxos em lote a partir dos eventos.
- Ao parar: destruir o motor (fecha o pcap) → SHA-256 em streaming → grava na sessão → escreve
  `sessao-<inicio>.sha256` (`<hash>  sessao-<inicio>.pcap`).
- Exportar pela SAF (`ACTION_CREATE_DOCUMENT`): `.pcap` e `.sha256`.
- Apagar sessão remove arquivo e linhas.

Testes JVM: `Evidencia` contra o SHA-256 de um arquivo conhecido (valor do `sha256sum`); formato da
linha `.sha256`; mapeamento evento → linha de fluxo.

Prova: `./gradlew testDebugUnitTest --tests '*Evidencia*' --tests '*Fluxo*'` → passa. No PC, depois
de exportar: `sha256sum -c sessao-*.sha256` → `OK`.

### Tarefa 11 — Tela de sessões e lista ao vivo [Kotlin — Claude]

- Tela inicial: botão Gravar/Parar, lista de sessões (data, duração, pacotes, bytes, hash abreviado).
- Ao vivo: conexões em ordem de atividade, com ícone e nome do app, domínio (marcando se veio de SNI
  ou DNS), IP:porta, protocolo, bytes ↑/↓; filtro por app e texto; atualização a cada 250 ms sem travar a rolagem.
- A mesma tela abre uma sessão antiga a partir do banco.

Prova: testes JVM do `ViewModel` (ordenação, filtro, junção domínio↔IP); no aparelho com o OK, a lista
mostra o navegador com o domínio do site aberto.

### Tarefa 12 — Detalhe do pacote [C — Brendon + tela Claude]

Arquivos: `native/src/dissecar.c` (Brendon), `native/tests/t_dissecar.c`, tela `ConexaoScreen.kt` (Claude).

- `sn_dissecar`: árvore em texto (uma linha por campo, indentação por camada): IP, UDP/TCP, DNS ou
  TLS ClientHello quando reconhecer, e o resto em hex + ASCII.
- A tela da conexão lista os pacotes do fluxo (lidos do pcap pela Tarefa 3) e abre a árvore de cada um.

Testes C: para as fixtures das Tarefas 1–4, os campos e valores da árvore batem com o `tshark -V`
(comparando campo a campo, não o texto inteiro).

Prova: `tools/testes-c.sh dissecar` → passa; no aparelho com o OK, abrir um pacote DNS e ver o nome.

### Tarefa 13 — Resumo por app e rastreadores [Kotlin — Claude]

- Lista de domínios de rastreadores: escolher a fonte e **conferir a licença** antes de embutir
  (candidatas: assinaturas de rede do Exodus Privacy; DuckDuckGo Tracker Radar, CC BY-NC-SA 4.0; lista
  da Disconnect). Registrar fonte, data e licença em `docs/rastreadores.md`.
- Casamento por sufixo de domínio (`ads.x.com` casa com `x.com`).
- Tela: por app, total de bytes, nº de domínios, nº de rastreadores e a lista de domínios.

Prova: testes JVM do casamento por sufixo (inclusive `notx.com` **não** casa com `x.com`) e da agregação.

### Tarefa 14 — Alertas [Kotlin — Claude]

Regras em Kotlin puro, com relógio e fuso injetados, cada uma disparando no máximo uma vez por app e
regra por sessão:

| Regra | Dispara quando |
|---|---|
| `MADRUGADA_OU_TELA_DESLIGADA` | fluxo novo entre 00:00 e 05:00 (hora local) ou com a tela desligada |
| `DOMINIO_NOVO` | o app fala com um domínio que não está em `dominio_visto` (a primeira sessão só aprende, não alerta) |
| `RASTREADOR` | domínio casa com a lista da Tarefa 13 |
| `PORTA_INCOMUM` | porta de destino fora de {53, 80, 123, 443, 853, 5228, 3478–3481} |
| `DNS_ESCONDIDO` | TCP/UDP 853 (DoT), ou 443 para provedor DoH conhecido (`dns.google`, `cloudflare-dns.com`, `1.1.1.1`, `8.8.8.8`, …), ou UDP 53 para servidor que não é o DNS virtual |

- Tela de alertas por sessão; notificação agrupada durante a gravação.

Prova: testes JVM por regra nos limites (04:59 dispara, 05:00 não; em UTC e em `America/Sao_Paulo`),
deduplicação e aprendizado da primeira sessão.

### Tarefa 15 — Prova final e documentação [Claude + Brendon]

- **No aparelho, só com o OK do Brendon:** sessão de 5 min com navegador, um app de rede social e
  uma consulta DNS; conferir lista, detalhe, resumo e alertas; exportar.
- No PC: `capinfos` e `tshark -r sessao.pcap -q -z expert` sem pacote malformado gerado pelo motor;
  `sha256sum -c` → OK; domínios do navegador batem com o histórico.
- `docs/estudo.md`: o que cada tarefa ensinou e o que fica para a fase 2.

## Bloqueios e itens a confirmar

- **B1:** criar o repo `Brendon978/sentinela` no GitHub (o Brendon cria; não há `gh` na máquina).
- **B2:** instalar `wireshark-cli`/`tcpdump` com sudo (o Brendon roda).
- **B3:** tipo de serviço em primeiro plano para VPN no Android 16 (lido na documentação na Tarefa 9).
- **B4:** licença da lista de rastreadores (Tarefa 13).
- **B5:** comportamento com o "DNS privado" da Samsung ligado; medido no aparelho na Tarefa 9.

## Riscos

- **Relé TCP** (Tarefa 7) é a parte mais difícil e pode tomar várias sessões de estudo; o app só
  navega de verdade depois dela. Depois da Tarefa 6, as Tarefas 8–11 podem avançar em paralelo com a 7, testando só UDP/DNS.
- **Bateria:** o laço `poll` só acorda com pacote; nada de espera ativa.
- **Apps que detectam VPN** (alguns bancos) podem recusar abrir durante a gravação: é esperado, e a
  gravação é por sessão (R3).
- **Uso legal:** só no próprio aparelho; o README avisa.

## Aceitação da v1

R1–R12 atendidos, com a prova da Tarefa 15: captura de 5 min no S25 FE, `.pcap` íntegro no tshark,
hash conferido, cada conexão com app e domínio quando houver, e as cinco regras de alerta com testes.

## Cobertura

| Requisito | Tarefas |
|---|---|
| R1, R2 | 1–7, 12 (C do Brendon com testes do Claude) |
| R3 | 9, 11 |
| R4 | 1, 2, 6, 7 |
| R5 | 4, 6, 7, 8, 9, 11 |
| R6 | 3, 12 |
| R7 | 13 |
| R8 | 14 |
| R9 | 3, 10 |
| R10 | 0 |
| R11 | 9 |
| R12 | 9, 11, 12, 15 |
