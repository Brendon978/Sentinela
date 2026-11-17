# Sentinela — identidade visual nova (design)

Data: 2026-11-17. Pedido do Brendon: "um design mais dahora pro app".

## Intenção e porquê

O app é para o próprio Brendon usar no dia a dia e para render **prints para o artigo**
acadêmico (forense de rede + IA). Hoje é o Material 3 padrão, escuro, com um roxo genérico
(`#B388FF`), sem fonte própria, e não conversa com o ícone (`arte/Sentinela_icon.jpeg`: azul-
petróleo profundo, verde e ciano neon, torre com olho, ondas de radar, circuitos). O visual novo
deve dar cara de **ferramenta de segurança séria**, coerente com o ícone, mais legível, e os
prints precisam funcionar num PDF (e, se impresso, em preto e branco).

## Metas

1. Tema próprio derivado do ícone, aplicado em todas as telas (cores, tipografia, formas).
2. Redesenho das telas principais: Início, Ao vivo (conexões / por app / alertas), Detalhe da
   conexão, Mapa da rede, Sessão salva, diálogo de exportação.
3. Hierarquia clara: números importantes grandes, dados técnicos em monoespaçada, alertas por
   **categoria** com cor **e** ícone/forma (não só cor).
4. **Modo claro opcional**, para prints de artigo (alto contraste, legível em escala de cinza).
5. Gravação com presença visual: indicador de "gravando" animado e discreto.

## Não-metas

- Não muda o que o app faz: motor, banco, regras, IA, exportação ficam iguais.
- Não muda a navegação (mesma máquina de telas em `MainActivity`).
- Não troca o ícone do launcher.
- Sem telas novas de funcionalidade.

## Antimetas (fracasso mesmo funcionando)

- Visual "HUD/terminal" carregado (brilho em tudo, linhas de varredura, radar decorativo): cansa
  e parece enfeite num artigo.
- Texto pequeno ou de baixo contraste (neon fino sobre escuro) que some no print.
- Informação codificada só em cor (categoria, origem do domínio) — falha em P&B e daltonismo.
- Uma hierarquia de "gravidade" entre regras fixas e IA nos prints: o artigo compara as duas, e
  a tela não pode sugerir de antemão que uma é mais grave que a outra.
- Animação que custe bateria ou trave a lista ao vivo (que recompõe a cada 100 ms).

## Restrições

- Kotlin + Jetpack Compose + Material 3, como hoje (`ui/Telas.kt`, `MainActivity.kt`).
- Sem bibliotecas grandes novas. Ícones: desenhar os poucos necessários como `ImageVector`
  (ou `material-icons-core`, que é pequeno); nada de `icons-extended` inteiro.
- Fontes com licença livre (OFL), empacotadas em `res/font` (sem baixar em tempo de execução,
  o app captura a rede e não deve depender dela).
- Contraste de texto ≥ 4,5:1 (WCAG AA) nos dois temas.
- A lista ao vivo continua rápida: nada de efeito por item que recalcule a cada lote.

## Abordagens consideradas

| | O que é | Prós | Contras |
|---|---|---|---|
| A | Só trocar o tema (cores/fonte/formas) | rápido, sem risco | telas seguem "lista simples" |
| **B** | **Tema novo + redesenho das telas principais + modo claro opcional** | prints com cara de ferramenta, leitura melhor | 2–3 sessões de trabalho |
| C | Visual HUD/terminal completo | impacto imediato | cansa, prejudica leitura, parece enfeite no artigo |

Escolhida: **B** (recomendação; o Brendon deixou a escolha comigo: "vai fazendo o que vc mesmo
recomenda").

## Decisões (minhas, a conferir)

### Paleta (tirada do ícone)

Escuro (padrão):
- fundo `#071A24` (azul-petróleo quase preto); superfícies `#0D2633` e `#12313F`
- primária (ação, destaque): verde neon `#3DF2A0`; secundária: ciano `#2FD3F5`
- texto principal `#E3F2F5`, secundário `#8FB3BD`
- categorias de alerta (ver abaixo): rede `#2FD3F5`, privacidade `#B98CFF`, horário e
  comportamento `#FFB547`, novidade `#3DF2A0`; perigo/erro `#FF5C6C` (só para estado, não alerta)
- gravando: vermelho `#FF5C6C` pulsando

Claro (para prints): fundo `#F7FAFB`, superfícies brancas com borda `#D5E2E6`, primária verde
escuro `#0B7A55`, secundária azul `#0B6E8A`, texto `#0B1F27`. Mesmas cores de categoria em tom
mais escuro. Valores finais ajustados para passar contraste AA.

### Tipografia

- Títulos e números: **Space Grotesk** (OFL), peso 600–700.
- Texto corrido: a do sistema (Roboto), para não pesar.
- Dados técnicos (IP, porta, hash, hex, bytes): **JetBrains Mono** (OFL).

### Formas e componentes

- Cartões com canto 16 dp, borda fina de 1 dp na cor da superfície mais clara (em vez de sombra).
- Selos (origem do domínio, protocolo, motivo de fim) em "pílula" monoespaçada pequena.
- Alertas: cartão com faixa lateral colorida **por categoria** + ícone próprio de cada categoria
  (formas diferentes, legível em P&B). Categorias, só na UI (um `when` sobre `Regra`, sem mexer
  no domínio nem no PDF), sem ranking de gravidade:
  - **Rede:** DNS_ESCONDIDO, PORTA_INCOMUM
  - **Privacidade:** RASTREADOR
  - **Comportamento:** MADRUGADA_OU_TELA_DESLIGADA, COMPORTAMENTO_ANOMALO (IA)
  - **Novidade:** DOMINIO_NOVO
  O alerta da IA ganha também um selo "IA" para o leitor do artigo distinguir regra fixa de IA.
- Ícones de tipo de aparelho no mapa, um por valor de `TipoAparelho` (rede/Mapa.kt): roteador,
  TV/streaming, impressora, câmera, Apple (iPhone/iPad/Mac), computador/NAS, desconhecido. Sem
  classificação nova.

### Telas

- **Início:** cabeçalho com a marca (nome + pequeno olho/torre estilizado). Cartão de gravação:
  botão grande; gravando, um anel de radar pulsa em volta do indicador e aparecem contadores
  (conexões, ↑↓, alertas, tempo). Sessões salvas como cartões com data, duração, pacotes,
  estado (selo "interrompida") e o hash em monoespaçada destacado. Alertas ignorados e o atalho
  do mapa ficam como seções secundárias.
- **Ao vivo:** faixa de resumo fixa no topo (conexões, ↑↓ total, alertas) e abas em estilo
  "segmentado". Linha de conexão: ícone do app, domínio em destaque, `PROTO ip:porta` em mono,
  selos, e uma barrinha proporcional ao volume ↑↓.
- **Por app:** barra de volume por app e contagem de rastreadores com selo.
- **Detalhe da conexão:** cabeçalho com o resumo do fluxo; cada camada do pacote (IP, TCP/UDP,
  DNS, TLS) num bloco com cor de camada, como no Wireshark; hex em mono com endereços apagados.
- **Mapa:** cartões por aparelho com ícone do tipo, IP em mono, portas como selos, nome/serviço.
- **Sessão salva / exportação:** mesmos cartões; diálogo de exportação com uma opção por linha,
  ícone e descrição curta.

### Modo claro

Alternância "Tema: escuro / claro" no Início (salva em `SharedPreferences`). Padrão: escuro. Não
segue o tema do sistema (o claro existe para prints, é escolha consciente).

### Animação

Só o pulso do radar enquanto grava (e, decidido na execução, durante a varredura do mapa, que
dura uns 20 s e precisa mostrar que está rodando) (`rememberInfiniteTransition`, ~1,6 s por ciclo) e transições
curtas entre abas. Pulso desligado quando o app sai da tela (Compose já para).

## Etapas e ponto de conferência

O trabalho para depois do tema e da tela de Início pronta nos dois temas: prints vão ao Brendon,
e só com o aval dele (paleta, fontes, formas) seguem as outras telas. Trocar paleta ou fonte
depois de redesenhar tudo obrigaria a refazer prints e contas de contraste.

## Deixado para quem constrói

- Organização do código do tema (`ui/tema/`: `Cores.kt`, `Tipos.kt`, `Tema.kt`) e quebra de
  `Telas.kt` em arquivos por tela, se ajudar.
- Desenho exato dos ícones vetoriais e do símbolo do cabeçalho.
- Ajuste fino de espaçamentos e tamanhos.

## Provas esperadas

- Build e testes JVM verdes (nenhuma lógica muda; testes de UI não existem hoje).
- Prints no aparelho de cada tela, nos dois temas, conferidos por mim e mostrados ao Brendon.
- Conferência de contraste das cores principais (AA) com uma conta simples (registrada).
- Print do modo claro convertido para escala de cinza continua legível.
