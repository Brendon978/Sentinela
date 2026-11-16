# Sentinela v1.2 (desempenho e estrutura) — plano

## Objetivo e fonte

Pedido do Brendon em 2026-11-16 ("pode fazer"), sobre as pendências anotadas no fim da v1.1
(memória `sentinela-app` e relato final da v1.1). Execução inline, como nas versões anteriores.
O celular está liberado para testes (ele avisa quando for usar).

| # | Requisito | Fonte |
|---|---|---|
| D1 | Laço do motor em `epoll`, sem remontar o conjunto de descritores a cada volta | pendência da v1 ("epoll no laço do motor") |
| D2 | Ciclo de vida da captura fora do `SessaoService`, numa classe `Captura` testável na JVM | pendência da v1 ("classe Captura no serviço") |
| D3 | Gravação de 5 s escreve só os fluxos que mudaram (e os alertas só quando mudaram), fora do laço que drena os eventos | simplify da v1.1, achado de eficiência 1 |
| D4 | Lote só com fins de fluxo não roda todas as regras: a IA julga só as conexões que terminaram | simplify da v1.1, achado de eficiência 4 |

Fora: reescrever a montagem da lista ao vivo (`Lista.aoVivo`), mapa da rede, mudança de formato
do pcap ou dos eventos C2.

## Arquitetura

- **C:** o motor ganha um `epoll` criado em `sn_motor_criar` (fechado em `sn_motor_destruir`).
  `fd_parar` e o tun entram uma vez. Os relés continuam só escrevendo `sn_estado.eventos`; o laço
  sincroniza: para cada fluxo, se `eventos` ou `fd` mudaram desde o último registro, faz
  `EPOLL_CTL_ADD/MOD/DEL` (campos novos em `sn_estado`: `fd_registrado`, `eventos_registrados`).
  `epoll_event.data.ptr` = `sn_fluxo*`. Invariante que já vale no `poll`: fluxo só é liberado no
  `tique` (antes da espera) e no `encerrar`, então os ponteiros do lote são válidos. Fechar o fd
  tira o registro do kernel; o laço só zera o estado registrado. Conversão `POLLIN/POLLOUT` ↔
  `EPOLLIN/EPOLLOUT` num ponto só (os relés seguem recebendo `revents` no formato do `poll`).
- **Kotlin:** `vpn/Captura.kt` recebe por construtor três costuras:
  `FonteEventos` (drenar bytes do motor; no serviço, `Motor.eventos`), `GravadorSessao`
  (`gravarParcial`; no serviço, o `Banco`) e o relógio. A `Captura` dona dos jobs: leitura (100 ms),
  gravação (5 s, em `Dispatchers.IO`, job próprio) e treino da IA; `parar()` cancela e espera
  gravação e treino; o serviço então para e encerra o motor, e `terminar()` drena o que sobrou e
  devolve a `Gravacao` (a parada em duas etapas deixa o `Motor.encerrar` no meio). O serviço fica com o Android: VPN, motor,
  notificações, tela e rede.
- **Gravação parcial:** `Alteracoes.desde(anterior: Map<Long, LinhaFluxo>, atual: List<LinhaFluxo>)`
  (puro) devolve só as linhas novas ou diferentes; `Banco.gravarParcial` recebe essas linhas,
  os alertas (ou null quando não mudaram) e o total de bytes da sessão (a soma deixa de vir das
  linhas passadas).
- **IA incremental:** `SessaoAtual.aplicar` com lote sem `FluxoNovo/Sni/Dns` mas com `FluxoFim`
  chama `Alertas.acrescentarAnomalias(alertas, terminadas, c)`, que julga só as linhas que
  terminaram e acrescenta um `COMPORTAMENTO_ANOMALO` por app ainda sem esse alerta (respeitando
  as exceções). O fim da sessão (`terminar`) continua com a avaliação completa.

## Tarefas e provas

1. **epoll no motor (D1).** ⚠ risco: laço de eventos e ciclo de vida de fd (base de tudo).
   Arquivos: `native/src/motor.c`, `motor_interno.h`, `relay_tcp.c`, `relay_udp.c` (só se algum
   caminho fechar fd sem passar pelo estado). Prova: `tools/testes-c.sh` → 103+ testes, 0 falhas
   (os testes de motor TCP/UDP exercitam o laço); teste novo `motor_muitos_fluxos_udp` (300 fluxos
   UDP simultâneos com eco, todos respondidos e fechados) e `motor_fd_reusado` (fluxo fecha, outro
   abre e recebe o mesmo número de fd; o eco do novo chega). Refatoração: o teste de muitos fluxos
   pode passar já com `poll`; é a rede de segurança, não RED. Medida antes/depois com a banca
   (`native/tests/banca.c`) registrada no relatório.
2. **Classe Captura (D2).** ⚠ risco: concorrência na parada (ordem gravação/treino/drenagem).
   Arquivos: `vpn/Captura.kt` (novo), `vpn/SessaoService.kt`, teste `vpn/CapturaTest.kt` (JVM,
   `kotlinx-coroutines-test` com relógio virtual). Cenários: (a) eventos da fonte chegam a
   `SessaoAtual`; (b) `parar()` espera a gravação em curso antes de drenar e devolver a
   `Gravacao`; (c) depois de `parar()` nenhuma gravação parcial acontece; (d) treino cancelado
   não chama `definirLinhaDeBase`. Prova: `./gradlew testDebugUnitTest --tests '*CapturaTest*'`
   → RED antes da classe, GREEN depois; aparelho: gravar 1 min, parar, sessão concluída com hash.
3. **Gravação parcial só do que mudou (D3).** ⚠ risco: dado de evidência no banco.
   Arquivos: `sessao/Alteracoes.kt` (novo), `dados/Banco.kt`, `vpn/Captura.kt`, testes
   `AlteracoesTest` (JVM) e `BancoTest` (instrumentado). Cenários: linha igual não volta; linha
   com bytes novos volta; fluxo novo volta; alertas iguais → null; bytes da sessão = total
   informado. Prova: JVM `--tests '*AlteracoesTest*'` RED→GREEN; `am instrument` → OK (9+ testes);
   aparelho: gravar, `am force-stop` no meio, reabrir → sessão interrompida com os mesmos fluxos
   da lista.
4. **IA só nas conexões que terminaram (D4).** Arquivos: `sessao/Alertas.kt`,
   `sessao/SessaoAtual.kt`, `AlertasTest`. Cenários: anomalia em linha terminada acrescenta um
   alerta; app que já tem o alerta não ganha outro; exceção do app impede; o conjunto
   (app, regra) depois de vários lotes incrementais é o mesmo da avaliação completa. Prova:
   `--tests '*AlertasTest*'` RED→GREEN.

Revisão independente ao fim das tarefas 1, 2 e 3 (risco); revisão final e `simplify` no fim; testes C e JVM completos,
instrumentados no aparelho e uma sessão real de alguns minutos antes de pedir o commit. Commit e
push só com o pedido do Brendon.

## Bloqueios

Nenhum. `kotlinx-coroutines-test` entra como dependência de teste (mesma versão das coroutines
já usadas).

## Aceitação

D1–D4 com as provas acima; nenhuma regressão nos 103 testes C, 70 JVM e 8 instrumentados;
sessão real no aparelho com hash conferido.
