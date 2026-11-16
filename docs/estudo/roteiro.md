# Roteiro de estudos — do bit à forense de rede

Este é o mapa: **o que** estudar, **em que ordem** e **onde pesquisar**. As explicações estão nas
aulas (`aulas/`), uma por módulo, com exercícios e respostas.

Você já sabe programar em C#, então vários pontos vão ser revisão rápida. Não tem pressa: o
objetivo é entender, não decorar.

## Como estudar

1. Leia a aula do módulo (`aulas/NN-...md`).
2. Faça os exercícios **no papel ou no terminal** antes de olhar as respostas.
3. Use as fontes do módulo para aprofundar o que ficou vago.
4. Marque aqui o que já estudou: troque `[ ]` por `[x]`.
5. Ao terminar um módulo, abra o código do Sentinela que usa aquele assunto (indicado em cada
   módulo) e tente entender o que ele faz.

Ordem recomendada: 1 → 2 → 3 → 4 → 5 → 6, e daí 7, 8, 9 e 10 podem ir em paralelo. O 11 entra
quando o artigo começar a ser escrito.

---

## Módulo 1 — Bits, bytes e números ([aula](aulas/01-bits-e-bytes.md))

- [x] Sistema binário: contar, converter de/para decimal na mão
- [x] Hexadecimal: por que existe, converter de/para binário e decimal
- [x] Bit, nibble, byte, palavra; quanto cabe em 8, 16, 32 e 64 bits
- [ ] Operações bit a bit: AND, OR, XOR, NOT, deslocamento (`<<`, `>>`)
- [ ] Máscaras: ligar, desligar e testar um bit
- [ ] Números negativos: complemento de dois (e o complemento de um, usado no checksum)
- [ ] Estouro (overflow) e o "vai um"
- [ ] Ordem dos bytes: big-endian e little-endian

**Fontes:** CS50 (Harvard, gratuito, legendado) — semana 0 e 1; "Código" de Charles Petzold
(livro, muito didático); qualquer calculadora de programador (a do Linux/Windows tem modo "Programador").

**No Sentinela:** `native/src/checksum.c`, `native/src/ip.c` (leitura de campos de cabeçalho).

## Módulo 2 — Linguagem C, vindo do C# ([aula](aulas/02-c-para-quem-sabe-csharp.md))

- [ ] Compilar e rodar: compilador, arquivo-objeto, link, executável
- [ ] Tipos de tamanho fixo (`uint8_t`, `uint32_t`…) e `size_t`
- [ ] Ponteiros: endereço, `*` e `&`, aritmética de ponteiros
- [ ] Arrays e a ausência de `.Length`; strings terminadas em `\0`
- [ ] `struct`, `enum`, `typedef`
- [ ] Memória: pilha (stack) e heap, `malloc`/`free`, vazamento, uso depois de liberar
- [ ] Comportamento indefinido (undefined behavior) e por que ele é perigoso
- [ ] Headers (`.h`) e implementação (`.c`); `#include`, `#define`
- [ ] Ferramentas: `gcc`/`clang`, `cmake`, `gdb`, AddressSanitizer
- [ ] Erros clássicos de segurança em C: estouro de buffer, inteiro que dá a volta, formato de `printf`

**Fontes:** CS50 semanas 1 a 5 (é em C!); "C Programming: A Modern Approach" (K. N. King);
"The C Programming Language" (Kernighan & Ritchie, o clássico, mais seco); Beej's Guide to C
(gratuito, em inglês, beej.us).

**No Sentinela:** `native/` inteiro; comece por `native/tests/teste.c` (pequeno e completo).

## Módulo 3 — Linux e terminal ([aula](aulas/03-linux-e-terminal.md))

- [ ] Navegar e manipular arquivos; caminhos absolutos e relativos
- [ ] Permissões, usuário, grupo, `sudo`
- [ ] Processos, sinais (`kill`, `Ctrl+C`), `ps`, `top`
- [ ] Redirecionamento e pipes (`>`, `2>`, `|`)
- [ ] "Tudo é arquivo": descritores de arquivo (0, 1, 2…)
- [ ] Gerenciador de pacotes (`pacman`)
- [ ] Comandos de rede: `ip`, `ss`, `ping`, `dig`, `curl`

**Fontes:** "The Linux Command Line" (William Shotts, gratuito em linuxcommand.org);
OverTheWire **Bandit** (jogo gratuito que ensina terminal); `man <comando>`.

## Módulo 4 — Redes: o caminho de um pacote ([aula](aulas/04-redes.md))

- [ ] Camadas (modelo TCP/IP e OSI) e encapsulamento
- [ ] Enlace: Ethernet, endereço MAC, ARP, switch
- [ ] Rede: IPv4, IPv6, máscara/CIDR, roteamento, TTL
- [ ] Endereços privados, NAT e CGNAT
- [ ] ICMP (`ping`, `traceroute`)
- [ ] Transporte: portas, UDP, TCP (handshake, seq/ack, janela, fechamento, estados)
- [ ] DNS (consulta, tipos A/AAAA/CNAME, resolvedor), DHCP
- [ ] HTTP e HTTPS; TLS (handshake, certificado, SNI); QUIC/HTTP3
- [ ] Wi-Fi: 802.11, ponto de acesso, WPA2/WPA3, modo monitor

**Fontes:** "Redes de Computadores e a Internet" (Kurose & Ross — tem em português);
"TCP/IP Illustrated, vol. 1" (Stevens); curso gratuito **Professor Messer Network+** (YouTube);
as RFCs citadas na aula (791, 8200, 768, 9293, 1035, 8446).

**No Sentinela:** fixtures em `native/tests/fixtures/` (abra com o tshark), `ip.c`, `udp.c`, `tcp.c`, `dns.c`, `sni.c`.

## Módulo 5 — Programação de rede ([aula](aulas/05-programacao-de-rede.md))

- [ ] Socket: o que é, `socket`, `bind`, `connect`, `send`/`recv`, `sendto`/`recvfrom`
- [ ] Cliente e servidor TCP e UDP mínimos em C
- [ ] Sockets não bloqueantes e `poll`
- [ ] Interface TUN: um "cabo de rede" de mentira que entrega pacotes IP a um programa
- [ ] Como uma VPN funciona por dentro (e como o Sentinela usa isso)

**Fontes:** **Beej's Guide to Network Programming** (gratuito, beej.us — leitura obrigatória);
`man 7 socket`, `man 2 poll`; documentação do `VpnService` do Android.

**No Sentinela:** `native/src/motor.c`, `relay_udp.c`, `relay_tcp.c`.

## Módulo 6 — Ferramentas de análise ([aula](aulas/06-ferramentas.md))

- [ ] Wireshark/tshark: abrir captura, filtros de exibição, seguir fluxo, estatísticas
- [ ] tcpdump e filtros de captura (BPF)
- [ ] Formato pcap
- [ ] nmap: descoberta de hosts e varredura de portas (só em rede autorizada)
- [ ] scapy: montar e ler pacotes em Python
- [ ] Zeek e Suricata: IDS de rede abertos

**Fontes:** "Practical Packet Analysis" (Chris Sanders); documentação do Wireshark
(wireshark.org/docs); amostras de captura em wiki.wireshark.org/SampleCaptures; nmap.org/book.

## Módulo 7 — Segurança da informação ([aula](aulas/07-seguranca.md))

- [ ] Confidencialidade, integridade, disponibilidade (CIA)
- [ ] Ameaça, vulnerabilidade, risco; superfície de ataque
- [ ] Ataques comuns: varredura, força bruta, phishing, MITM, DoS, SQL injection, XSS
- [ ] Defesa em camadas: firewall, WAF, IDS/IPS, SIEM, SOAR, EDR
- [ ] Criptografia na prática: hash, simétrica, assimétrica, certificado
- [ ] Frameworks: MITRE ATT&CK, Cyber Kill Chain, OWASP Top 10

**Fontes:** TryHackMe (trilhas "Pre Security" e "SOC Level 1", várias salas gratuitas);
OWASP Top 10 (owasp.org); MITRE ATT&CK (attack.mitre.org); DVWA para praticar em laboratório.

## Módulo 8 — Forense digital e de rede ([aula](aulas/08-forense.md))

- [ ] Princípios: troca de Locard, preservação, documentação
- [ ] Cadeia de custódia (no Brasil: CPP, arts. 158-A a 158-F, desde a Lei 13.964/2019)
- [ ] Integridade da evidência: hash (SHA-256), cópia de trabalho
- [ ] Ordem de volatilidade (RFC 3227); norma ISO/IEC 27037
- [ ] Forense de rede: captura completa x metadados de fluxo; linha do tempo
- [ ] Atribuição: o que um IP prova e o que não prova
- [ ] Laudo/relatório pericial: estrutura e linguagem
- [ ] Leis: Marco Civil da Internet, LGPD, Lei 12.737/2012, Lei 9.296/96

**Fontes:** "Network Forensics: Tracking Hackers through Cyberspace" (Davidoff & Ham);
"The Practice of Network Security Monitoring" (Richard Bejtlich); "Tratado de Computação
Forense" (Jesus P. Velho, org. — referência brasileira); RFC 3227; textos das leis no planalto.gov.br.

**No Sentinela:** sessões com `.pcap` + SHA-256 (Tarefa 10 do plano).

## Módulo 9 — Android por dentro ([aula](aulas/09-android.md))

- [ ] Arquitetura: Linux por baixo, apps isolados, UID por app
- [ ] Permissões e por que acessibilidade é tão perigosa
- [ ] `adb` e depuração
- [ ] `VpnService`: como um app vira a VPN do aparelho
- [ ] O que dá e o que não dá sem root

**Fontes:** documentação oficial em developer.android.com (VpnService, Permissions);
"Android Security Internals" (Nikolay Elenkov).

## Módulo 10 — Dados e IA para detecção ([aula](aulas/10-dados-e-ia.md))

- [ ] Python para dados: pandas, gráficos
- [ ] Estatística básica: média, mediana, desvio, distribuição, percentil
- [ ] Do pacote ao fluxo: o que são "features" (duração, bytes, pacotes, portas…)
- [ ] Aprendizado supervisionado x não supervisionado
- [ ] Detecção de anomalias: Isolation Forest, autoencoder
- [ ] Métricas: matriz de confusão, precisão, revocação (recall), F1, taxa de falso positivo
- [ ] Armadilhas: classes desbalanceadas, vazamento de dados, treinar e testar no mesmo dado
- [ ] Datasets: CIC-IDS2017, UNSW-NB15, CTU-13

**Fontes:** curso gratuito "Machine Learning" do Google (developers.google.com/machine-learning/crash-course);
"Mãos à Obra: Aprendizado de Máquina com Scikit-Learn, Keras & TensorFlow" (Aurélien Géron, em português);
documentação do scikit-learn; artigos originais dos datasets.

## Módulo 11 — Pesquisa e escrita acadêmica ([aula](aulas/11-pesquisa.md))

- [ ] Como ler um artigo (resumo → conclusão → figuras → resto)
- [ ] Onde buscar: Google Acadêmico, Portal de Periódicos CAPES, IEEE Xplore, anais do SBSeg (SBC)
- [ ] Estrutura: introdução, trabalhos relacionados, método, resultados, discussão, conclusão
- [ ] Citação e referências (ABNT), gerenciador de referências (Zotero)
- [ ] Ética em pesquisa: consentimento, anonimização, CEP
- [ ] Como escolher programa e orientador de mestrado

**Fontes:** "Metodologia do Trabalho Científico" (Severino); guia da biblioteca da sua faculdade;
Zotero (gratuito).
