# Sentinela v1 — relatório

Data: 2026-11-16. Plano: `docs/superpowers/plans/2026-11-13-sentinela-v1.md`.

## Entregue

| Tarefa | O que ficou pronto |
|---|---|
| 0 | Projeto Gradle + NDK 30, testes C no PC com AddressSanitizer/UBSan, fixtures pelo scapy com o tshark de oráculo |
| 1–2 | Checksum, cabeçalhos IPv4/IPv6 (com extensões), UDP, TCP, montagem de pacotes (iguais byte a byte aos do scapy) |
| 3 | Gravação e leitura de `.pcap` (Raw IP), filtro por fluxo |
| 4 | Respostas DNS (com compressão) e SNI do TLS ClientHello (inclusive partido em vários segmentos) |
| 5 | Tabela de fluxos com expiração por relógio injetado |
| 6 | Motor: laço `poll`, relé UDP, DNS virtual, eventos para o Kotlin, dois relógios (parede e monotônico) |
| 7 | Relé TCP: handshake, janela, FIN/RST, retransmissão NewReno, sondas de keepalive e janela zero |
| 8 | Ponte JNI e decodificador de eventos |
| 9 | VpnService por sessão, dono da conexão, escolha da rede real (mesmo com Tailscale ligado) |
| 10 | Sessões salvas: SHA-256, `.sha256`, banco SQLite (versão 2, com migração) |
| 11 | Telas: início, conexões ao vivo/salvas com busca |
| 12 | Dissecador de pacotes e lista de pacotes por conexão |
| 13 | Resumo por app e lista própria de rastreadores |
| 14 | Alertas por regras fixas, notificação, alertas salvos |

## Provas

- **C no PC:** `tools/testes-c.sh` → 98 testes, 0 falhas, 1 pulado (o eco UDP em IPv6 local,
  porque o PC não tem IPv6; o caminho IPv6 do tun é coberto pelo teste do DNS virtual IPv6).
- **Kotlin na JVM:** `./gradlew testDebugUnitTest` → todos passam.
- **No aparelho** (Galaxy S25 FE, Android 16): testes do banco (`am instrument`, 4 testes OK) e
  uso real: três sessões gravadas com o navegador, apps em segundo plano e um site de notícias.
- **Evidência:** `.pcap` de 2.709 pacotes trazido ao PC: `sha256sum -c` → **SUCESSO**; o tshark
  leu tudo como Raw IP, **0 checksums errados**, SNIs do Chrome e da Wikipédia visíveis.
- **Revisões independentes** nas tarefas de risco (4, 6, 7, 8/9) e revisão final. Achados reais
  corrigidos com teste; ver `.pmedico/execucoes/sentinela-v1/` enquanto a execução existir.

## O que os testes no aparelho mostraram (bom para o artigo)

- **Atribuição por app funciona** para apps (Chrome, WhatsApp, Play Services, Meta Services,
  CapCut). Consultas DNS do próprio Android e NTP não têm app dono: aparecem como sistema.
- **Apps falam em segundo plano:** o CapCut abriu conexão sem estar em uso.
- **O Android tentou DNS sobre TLS (porta 853)** no DNS virtual e voltou ao DNS comum quando falhou
  ("DNS privado automático").
- **Regra fixa gera falso positivo:** o WhatsApp usa a porta 5222 normalmente e caiu em "porta
  incomum". Exatamente o tipo de alarme falso que a comparação regras × IA vai medir.

## Limitações conhecidas (declarar no artigo)

1. Sem root, só o tráfego do próprio celular; nada de outros aparelhos da rede.
2. HTTPS continua cifrado: o domínio vem do SNI ou do DNS. Com ECH, o SNI é o nome público do
   provedor (ex.: `cloudflare-ech.com`), não o site.
3. QUIC (UDP 443) mostra o domínio só pelo DNS; "Forçar TCP" contorna.
4. O dono da conexão é consultado até ~100 ms depois do início: UDP muito curto pode virar
   "desconhecido".
5. Fragmentos IP e ICMP (ping) são descartados na v1.
6. Os fluxos vão para o banco no fim da sessão: se o app morrer no meio, o `.pcap` fica, mas a
   lista de conexões daquela sessão se perde.
7. Se a fila de eventos estourar (4 MiB), eventos são descartados e contados; um fluxo cujo início
   se perdeu some da lista.
8. A lista de rastreadores é curta (~60 domínios): deixa passar rastreadores menos conhecidos.
9. Enquanto grava, o Tailscale (ou outra VPN) fica desligado: o Android aceita uma VPN por vez.

## Próximos passos sugeridos

- Fase 2: mapa dos aparelhos da rede (mDNS, SSDP, varredura em rede autorizada).
- Linha de base por app com IA (Isolation Forest sobre as features dos fluxos): a parte de IA
  do artigo.
- Exportar a sessão já anonimizada (IPs, nomes de aparelho), para usar dados de amigos no artigo.
- Sensor no PC/notebook com o mesmo motor em C (é Linux), em laboratório virtual.

---

# v1.1 (celular) — 2026-11-16

Plano: `docs/superpowers/plans/2026-11-16-sentinela-v1.1-mobile.md`.

| | Entregue | Prova |
|---|---|---|
| M1 | Ícone adaptativo a partir de `arte/Sentinela_icon.jpeg` | gaveta de apps no aparelho |
| M2 | Sessão criada no início, gravada a cada 5 s, recuperada como "interrompida" se o app morrer | `force-stop` no meio: sessão volta com hash, 589 pacotes e 58 conexões |
| M3 | SNI marcado quando o ClientHello usa ECH (`SNI·ECH`) | fixture com ECH conferida no tshark |
| M4 | Ignorar uma regra para um app (toque longo), com "Desfazer" | aparelho: 3 alertas → 2 |
| M5 | CSV das conexões, normal e anonimizado (HMAC com sal por exportação) | aparelho: 504 linhas; nenhum IP/domínio real (achado e corrigido: IP do Wi-Fi como origem no QUIC) |
| M6 | Relatório em PDF (identificação, integridade, cadeia de custódia, por app, alertas, domínios) | aparelho + `pdftotext` |
| M7 | Mapa da rede (mDNS, SSDP, portas), com aviso de rede autorizada; pede `ACCESS_LOCAL_NETWORK` (Android 17) | funcionou depois da permissão (antes, `EPERM`) |
| M8 | IA de linha de base por app (Isolation Forest) e alerta "Comportamento fora do padrão" com o motivo | aparelho: 250 conexões julgadas, 7 acima do limiar (2,8%) |

## IA — decisões de método (para o artigo)

Revisão independente com experimento + testes no aparelho levaram a estas escolhas:

1. **Atributos.** Contínuos na floresta: log do volume enviado/recebido, log de pacotes, log da
   duração, hora como seno/cosseno (23h fica perto de 0h). Categóricos fora da floresta: porta e
   estado da tela entram como frequência no histórico do app e só contam quando **nunca** foram
   vistos (porta minoritária mas conhecida dava 14% de alarme falso dentro da floresta).
2. **Novidade.** O Isolation Forest original não separa um ponto novo além da faixa conhecida (ele
   vira "borda"). A checagem de faixa entra **só na raiz**, com folga proporcional e **piso por
   atributo** (≈4,5× no volume, ≈2 h no horário). Aplicada em todo nó, inflava o alarme falso a 20%;
   sem piso, um histórico de 1 minuto acusava tudo uma hora depois.
3. **Histórico.** Só conexões encerradas de sessões concluídas, sem as que a própria IA já acusou;
   mínimo de 100 conexões **e** 3 sessões por app. Atributo quase constante no histórico fica fora
   da floresta.
4. **Limiar.** p99 das notas num pedaço do histórico (20%) que o modelo não viu, com piso 0,6.
5. **Julgamento.** Só conexões encerradas (volume e duração completos). Nota e limiar de cada
   conexão ficam no banco e no CSV (`nota_ia`, `limiar_ia`) para calcular precisão, recall e taxa
   de falso positivo; a sessão registra quantos apps tinham modelo (`ia_apps`).
6. **Motivo.** Vem do modelo: atributo do corte que isolou o ponto (voto das árvores) ou o atributo
   novo na raiz.

Medido com dados sintéticos (testes): alarme falso < 4% com o histórico mínimo; porta nunca usada e
tela desligada pela primeira vez detectadas em > 90%.

## Limitações novas

- O mapa da rede não vê aparelhos que não anunciam nada e não têm nenhuma das portas testadas.
- Nos dados móveis não há mapa: não existem vizinhos na rede local.
- A IA só julga apps com histórico suficiente; nas primeiras sessões, só as regras fixas valem.
