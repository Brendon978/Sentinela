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
