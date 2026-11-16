# Sentinela v1.1 (celular) — plano

## Objetivo e fonte

Pedido do Brendon em 2026-11-16 ("pro mobile, pode ir fazendo"), a partir da lista de melhorias
da conversa. Execução inline (mesma modalidade da v1). O celular está liberado para testes; ele
avisa quando for usar.

| # | Requisito |
|---|---|
| M1 | Ícone próprio a partir de `arte/Sentinela_icon.jpeg` |
| M2 | Conexões salvas durante a gravação (crash no meio não perde a lista); sessão interrompida é recuperada ao abrir o app |
| M3 | SNI marcado quando o ClientHello usa ECH (o nome é do provedor, não do site) |
| M4 | Exceções de alerta por app e regra ("ignorar esta regra para este app") |
| M5 | Relatório da sessão em PDF (hash, metadados, cadeia de custódia, apps, alertas, domínios) |
| M6 | Exportação dos fluxos em CSV, com opção anonimizada (IPs e domínios trocados por pseudônimos estáveis) |
| M7 | Mapa da rede: aparelhos do Wi-Fi por mDNS, SSDP e varredura leve de portas, só em rede autorizada |
| M8 | IA no celular: linha de base por app (Isolation Forest sobre features dos fluxos de sessões anteriores) e alerta de comportamento anômalo com o motivo |

Fora: `epoll` no motor e classe `Captura` (ficam para depois).

## Tarefas e provas

1. **Ícone** — mipmaps adaptativos; prova: print do launcher no aparelho.
2. **Gravação contínua no banco** — sessão criada no início (estado `gravando`), fluxos e alertas
   gravados a cada 5 s (upsert), fechamento grava hash e fim; ao abrir, sessão `gravando` sem
   serviço vira `interrompida` com hash do pcap. ⚠ risco (dado/evidência). Prova: testes
   instrumentados do Banco (upsert, recuperação) e teste no aparelho matando o processo.
3. **ECH** — `sn_tls_sni` informa a extensão ECH (0xfe0d); evento SNI ganha 1 byte de flag
   (contrato C2: campo novo no fim; o Kotlin aceita sem ele). Prova: teste C com fixture de
   ClientHello com ECH montada a partir do real; teste JVM do decodificador.
4. **Exceções de alerta** — tabela `excecao(pacote, regra)`; `Alertas.Contexto.excecoes`; toque
   longo no alerta. Prova: teste JVM.
5. **CSV de fluxos (normal e anonimizado)** — Kotlin puro; pseudônimo = HMAC-SHA256 com sal
   aleatório por exportação. Prova: teste JVM (formato, estabilidade dentro do arquivo,
   nada do original vaza).
6. **Relatório PDF** — conteúdo montado em Kotlin puro (testável) e desenhado com
   `android.graphics.pdf.PdfDocument`. Prova: teste JVM do conteúdo; PDF gerado no aparelho e
   conferido no PC (`pdftotext`).
7. **Mapa da rede** — parser de SSDP, enumeração da sub-rede, junção dos achados (JVM); mDNS com
   `NsdManager`, SSDP por multicast, varredura TCP de poucas portas com prazo curto. Aviso de uso
   só em rede autorizada antes de cada varredura. Prova: testes JVM + varredura na rede de casa.
8. **IA de linha de base** — features por fluxo; Isolation Forest em Kotlin (semente fixa);
   treino com fluxos das sessões anteriores do mesmo app; pontuação na sessão; regra
   `COMPORTAMENTO_ANOMALO` com o atributo que mais pesou. ⚠ base do artigo. Prova: testes JVM
   com dados sintéticos (o ponto fora do padrão tem a maior nota) e uso no aparelho.

Revisão independente nas tarefas 2 e 8 e revisão final; `simplify` no fim; commit e push só com
o pedido do Brendon (o repositório já está publicado).
