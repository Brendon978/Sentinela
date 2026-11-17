# Sentinela — identidade visual nova (plano)

## Objetivo e fonte

Fonte: design aprovado pelo Brendon em 2026-11-17 ("pode fazer"),
`docs/superpowers/specs/2026-11-17-sentinela-visual-design.md`. Execução inline. Celular liberado
para testes ("celular é seu").

| # | Requisito (seção do design) |
|---|---|
| V1 | Tema próprio do ícone: paleta escura e clara, Space Grotesk + JetBrains Mono, cartões 16 dp com borda, selos em pílula (Paleta, Tipografia, Formas) |
| V2 | Contraste ≥ 4,5:1 nos dois temas (Restrições) |
| V3 | Modo claro opcional, alternado no Início e salvo (Modo claro) |
| V4 | Início: marca, botão de gravar com pulso de radar, contadores, sessões em cartões com hash (Telas) |
| V5 | Ao vivo: faixa de resumo, abas segmentadas, linha com barra de volume; Por app com barra e rastreadores (Telas) |
| V6 | Alertas por categoria (rede, privacidade, comportamento, novidade), cor + ícone, selo "IA", só na UI (Formas) |
| V7 | Detalhe: camadas em blocos coloridos, hex em mono (Telas) |
| V8 | Mapa com ícone por `TipoAparelho`; sessão salva e diálogo de exportação no mesmo estilo (Telas) |
| V9 | Ponto de conferência: tema + Início nos dois temas aprovados antes das outras telas (Etapas) |
| V10 | Nada de lógica muda; lista ao vivo continua leve; só o pulso anima (Não-metas, Antimetas, Animação) |

## Arquitetura

- `ui/tema/Cores.kt` (duas paletas como `ColorScheme` + cores extras de categoria/estado num
  `CompositionLocal` `CoresSentinela`), `ui/tema/Tipos.kt` (`FontFamily` das duas fontes e a
  `Typography`), `ui/tema/Tema.kt` (`TemaSentinela(claro: Boolean, conteudo)`), `ui/tema/Contraste.kt`
  (luminância relativa WCAG, função pura).
- Fontes OFL em `app/src/main/res/font/` (`space_grotesk_*.ttf`, `jetbrains_mono_*.ttf`), baixadas
  dos repositórios oficiais no GitHub; licenças em `app/src/main/assets/licencas/`.
- Preferência do tema: `SharedPreferences("sentinela")`, chave `tema_claro`.
- `ui/Componentes.kt`: `Cartao`, `Selo`, `Pulso`, `BarraVolume`, `ResumoNumero`, ícones vetoriais.
- `ui/Categorias.kt`: `categoria(regra): Categoria` (enum REDE, PRIVACIDADE, COMPORTAMENTO,
  NOVIDADE) — pura, testada.
- `ui/Camadas.kt`: separa o texto do dissecador (camada = linha sem recuo; campos com dois
  espaços) em blocos — pura, testada.
- Telas continuam em `ui/Telas.kt` (pode ser dividido por tela) e `MainActivity.kt` só troca o
  tema e passa a preferência.

## Tarefas e provas

1. **Tema base (V1, V2).** ⚠ base (todas as telas dependem). Cores, tipos, tema, fontes, teste
   `ContrasteTest` (JVM): texto principal/secundário, primária e cores de categoria sobre fundo e
   superfícies, nos dois temas, ≥ 4,5 (valor esperado da norma WCAG 2.x; conferir a função com o
   par preto/branco = 21:1). Prova: `./gradlew testDebugUnitTest --tests '*ContrasteTest*'`
   RED→GREEN; `assembleDebug` ok.
2. **Início e modo claro (V3, V4).** Componentes, tela de Início, pulso de radar, alternância de
   tema salva. Prova: build; prints no aparelho do Início parado e gravando, nos dois temas.
   **Parada (V9):** prints ao Brendon; segue só com o aval dele.
3. **Ao vivo, Por app e Alertas (V5, V6).** Teste `CategoriasTest` (cada `Regra` numa categoria;
   valores do design) RED→GREEN. Prova: prints gravando com tráfego do Chrome, nos dois temas;
   rolagem da lista sem engasgo visível.
4. **Detalhe da conexão (V7).** Teste `CamadasTest` com o texto de uma fixture real
   (`tls_client_hello_sni`, saída do dissecador) RED→GREEN. Prova: print do detalhe de uma conexão
   TLS e de uma DNS.
5. **Mapa, sessão salva e exportação (V8).** Prova: prints da sessão salva, do diálogo de
   exportação e do mapa (rede de casa ou mapeamento feito pelo Brendon; não rodo o mapa na rede
   do trabalho).
6. **Fechamento (V2, V10).** Print do modo claro em escala de cinza (`magick -colorspace Gray`)
   legível; suíte JVM e build; revisão final e `simplify`; commit e push só com o pedido dele.

## Bloqueios

Nenhum. Download das fontes depende de acesso ao GitHub; sem ele, a fonte do sistema fica no lugar
e o plano segue (anotado).

## Aceitação

V1–V10 com as provas acima; testes JVM existentes continuam verdes; nenhum arquivo fora de `ui/`,
`MainActivity.kt`, `res/` e `assets/` muda (exceto docs).
