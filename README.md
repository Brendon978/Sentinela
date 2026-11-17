# Sentinela

App Android pessoal que captura o tráfego de rede do próprio celular por uma VPN local (sem root),
mostra qual app gerou cada conexão e guarda cada captura como evidência (`.pcap` + SHA-256).

Projeto de estudo de redes, C e computação forense. A casca é Kotlin/Compose; o miolo que lê e
reencaminha pacotes é C, compilado pelo NDK.

> **Uso legal:** só no seu próprio aparelho. Capturar comunicação de outras pessoas sem autorização
> é crime no Brasil (Lei 9.296/96 e Lei 12.737/2012).

## O que a v1 faz

- **Grava por sessão** (botão Gravar/Parar): VPN local, sem root; o próprio app fica fora dela.
- **Lista ao vivo** de conexões com o app dono (ícone e nome), domínio (pelo SNI do TLS ou pelo
  DNS), IP, porta, protocolo e bytes ↑↓, com busca.
- **Detalhe da conexão** com os pacotes dela, cada um dissecado camada por camada (IP, TCP/UDP,
  DNS, TLS ClientHello, hex), com checksums conferidos.
- **Por app**: tráfego, domínios e rastreadores conhecidos de cada app.
- **Alertas** por regras fixas: madrugada/tela desligada, domínio novo, rastreador, porta incomum
  e DNS fora do caminho normal (DoT, DoH, DNS direto). Notificação durante a gravação.
- **Sessões salvas** com `.pcap` (Raw IP), `.sha256` no formato do `sha256sum` e banco SQLite;
  exportação pelo seletor de arquivos do Android.
- **Forçar TCP** (opcional): bloqueia QUIC para os apps usarem TCP e o SNI aparecer.
- **v1.1:** gravação salva a cada 5 s (e recuperada se o app morrer), marca de ECH no SNI (com o DNS separando o ECH falso do Chrome),
  ignorar alerta por app, exportação em CSV (normal e anonimizada) e relatório em PDF, mapa da rede
  Wi-Fi (só em rede autorizada) e IA de linha de base por app (Isolation Forest).
- **v1.2:** motor em `epoll`, captura separada do serviço (testada na JVM), gravação de 5 s só
  do que mudou e IA julgando só as conexões que terminaram.

Resultado completo, provas e limitações: [docs/relatorio-v1.md](docs/relatorio-v1.md).

## Estrutura

| Pasta | O que tem |
|---|---|
| `app/` | app Android (Kotlin + Compose) |
| `native/include/` | headers do motor em C (os contratos) |
| `native/src/` | motor em C; `jni.c` é a ponte com o Kotlin |
| `native/tests/` | testes do motor, rodam no PC com AddressSanitizer |
| `native/tests/fixtures/` | pacotes de teste (`.hex` + `.pcap`), gerados pelo scapy |
| `tools/` | scripts de teste e de fixtures |
| `docs/superpowers/plans/` | plano da v1 |
| `docs/estudo/` | roteiro e aulas de estudo (bits, C, redes, forense, IA) |
| `docs/artigo/` | ideia e rumo do artigo acadêmico |

## Requisitos

- Android SDK em `~/android-sdk` com NDK `30.0.16248370` e CMake `4.1.2`
- `clang`, `cmake` e `ninja` no PC
- `tshark` (`sudo pacman -S wireshark-cli`) para conferir pacotes
- scapy no venv do projeto: `python3 -m venv tools/.venv && tools/.venv/bin/pip install scapy`

## Como rodar

```sh
tools/testes-c.sh            # todos os testes C
tools/testes-c.sh ip         # só os que têm "ip" no nome
tools/.venv/bin/python tools/fixtures/gerar.py   # regera as fixtures
tools/fixtures/oraculo.sh v4_udp_simples         # como o Wireshark vê uma fixture
./gradlew testDebugUnitTest  # testes Kotlin na JVM
./gradlew assembleDebug      # APK em app/build/outputs/apk/debug/
```

Testes no aparelho (banco SQLite), sem desinstalar o app no fim:

```sh
./gradlew installDebug installDebugAndroidTest
adb shell am instrument -w com.brendon978.sentinela.test/androidx.test.runner.AndroidJUnitRunner
```

(`./gradlew connectedDebugAndroidTest` também roda, mas desinstala o app e apaga as sessões.)

Conferir uma sessão exportada no PC:

```sh
sha256sum -c sessao-<inicio>.sha256
capinfos sessao-<inicio>.pcap
tshark -r sessao-<inicio>.pcap -Y tls.handshake.extensions_server_name -T fields -e tls.handshake.extensions_server_name
```
