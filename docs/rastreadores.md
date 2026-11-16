# Lista de rastreadores

Fonte: `app/src/main/java/com/brendon978/sentinela/sessao/Rastreadores.kt`.

## Origem e licença

Lista **própria**, curta (cerca de 60 domínios), montada em 2026-11-16 com domínios públicos e
amplamente documentados de SDKs de anúncios, análise de uso, atribuição de instalação,
engajamento e diagnóstico de falhas. Não foi copiada de nenhuma lista com licença restritiva.

Listas maiores para importar no futuro, com a atribuição que a licença pede:

| lista | licença | observação |
|---|---|---|
| DuckDuckGo Tracker Radar | CC BY-NC-SA 4.0 | uso não comercial, atribuição e compartilhamento pela mesma licença |
| Exodus Privacy (assinaturas de rede) | conferir no repositório antes de usar | foco em SDKs de apps Android |
| Disconnect tracking protection | conferir no repositório antes de usar | usada pelo Firefox |

## Critérios

- Entra só domínio cuja função principal é rastrear, exibir anúncio ou coletar telemetria.
- Domínio que também é o serviço principal de um app (ex.: `graph.facebook.com` para o próprio
  Facebook) fica de fora, para não marcar o uso normal do app como rastreamento.
- Casamento por sufixo de domínio: `ad.doubleclick.net` casa com `doubleclick.net`, mas
  `notdoubleclick.net` não.

## Limitação

Uma lista curta deixa passar rastreadores menos conhecidos (falso negativo). Para o artigo, isso
entra como limitação da regra fixa `RASTREADOR`.
