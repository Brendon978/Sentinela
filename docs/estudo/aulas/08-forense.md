# Aula 8 — Forense digital e de rede

A área que você mais curte. Aqui está o que diferencia "olhar uns pacotes" de **perícia**: método,
integridade e documentação.

---

## 1. O que é forense digital

É aplicar método científico para **identificar, preservar, coletar, examinar, analisar e
apresentar** evidências digitais de forma que elas sejam aceitas (num processo, numa empresa,
numa investigação). As fases:

1. **Identificação:** o que pode conter evidência? (celular, servidor, logs, tráfego)
2. **Preservação:** impedir que se altere (isolar, bloquear escrita, calcular hash)
3. **Coleta:** copiar de forma verificável
4. **Exame e análise:** extrair e interpretar, **sempre na cópia**
5. **Apresentação:** o laudo, claro e reproduzível

**Princípio de Locard:** "todo contato deixa um rastro". No digital: toda ação deixa log,
metadado, entrada de cache, pacote.

## 2. Cadeia de custódia

É o registro de **toda a vida da evidência**: quem coletou, quando, onde, como, quem teve acesso,
onde ficou guardada. Se ela se rompe, a defesa pode questionar se a evidência é a mesma.

No Brasil, a cadeia de custódia está no **Código de Processo Penal, artigos 158-A a 158-F**,
incluídos pela **Lei 13.964/2019** (o "pacote anticrime"). Ela lista as etapas: reconhecimento,
isolamento, fixação, coleta, acondicionamento, transporte, recebimento, processamento,
armazenamento e descarte.

## 3. Integridade: hash

O jeito de provar que a evidência não mudou é o **hash** (aula 7):

1. Coletou → calcula o SHA-256 e registra.
2. Trabalha sempre numa **cópia**.
3. Antes de apresentar → calcula de novo. Bateu? Ninguém alterou.

```sh
sha256sum sessao.pcap > sessao.sha256     # registra
sha256sum -c sessao.sha256                # confere depois: "sessao.pcap: OK"
```

É exatamente o que o Sentinela faz no fim de cada sessão.

## 4. Ordem de volatilidade

Coleta-se primeiro o que some mais rápido (RFC 3227):

1. registradores e cache da CPU
2. memória RAM, tabelas de rede (conexões, ARP), processos
3. arquivos temporários
4. disco
5. logs remotos e backups

**Tráfego de rede é o mais volátil de todos**: se não foi capturado na hora, não existe mais.
Por isso existe a ideia de *forensic readiness* (prontidão forense): já estar capturando antes do
incidente. Um sensor como o Sentinela é isso.

Normas de referência: **ISO/IEC 27037** (identificação, coleta e preservação de evidência digital)
e **ISO/IEC 27042** (análise e interpretação).

## 5. Forense de rede

Duas formas de guardar tráfego:

| | captura completa (pcap) | metadados de fluxo (NetFlow, Zeek `conn.log`) |
|---|---|---|
| guarda | todos os bytes | quem falou com quem, quando, quanto, por quanto tempo |
| espaço | enorme | pequeno (dá para guardar meses) |
| com HTTPS | conteúdo cifrado de qualquer jeito | quase a mesma informação útil |
| privacidade | invasiva | bem menos |

Na prática, guarda-se fluxo por muito tempo e pcap por pouco tempo, ou só do que foi marcado como
suspeito. A sua pergunta de pesquisa mora aqui: **dá para fazer a triagem só com o fluxo?**

### Linha do tempo

A peça central de qualquer análise é a **linha do tempo**: ordenar todos os eventos (conexões,
DNS, logins, alertas) e reconstruir a história. Cuidado com:

- **Fuso horário:** guarde sempre em UTC e diga isso no laudo.
- **Relógio errado:** o relógio do aparelho pode estar adiantado. Registre a diferença para uma
  fonte confiável (NTP) no momento da coleta.

## 6. Atribuição: o que um IP prova

Um IP mostra **de onde o pacote veio na rede**, não **quem** estava no teclado:

- VPN, Tor e proxies escondem a origem real.
- Máquinas invadidas (botnets) atacam em nome de outros.
- **CGNAT**: o mesmo IP público é usado por muitos clientes ao mesmo tempo (aula 4).
- Wi-Fi aberto ou compartilhado: qualquer um na rede usa o mesmo IP.

O laudo honesto diz "partiu do IP X, na porta Y, no horário Z (UTC)", e não "foi a pessoa P".
Chegar à pessoa exige cruzar com outras provas (registros do provedor, com ordem judicial).

## 7. Laudo pericial

Estrutura comum:

1. **Preâmbulo:** quem é o perito, quem pediu, quando.
2. **Histórico / objetivo:** o que se quer saber (os **quesitos**).
3. **Material examinado:** descrição e **hashes**.
4. **Metodologia:** ferramentas (com versão), passos — tem que dar para **outro perito repetir**.
5. **Exames e resultados.**
6. **Respostas aos quesitos.**
7. **Conclusão.**

Linguagem: objetiva, sem opinião, sem afirmar além do que a evidência mostra.

## 8. Leis que você precisa conhecer

| lei | o que importa aqui |
|---|---|
| **Marco Civil da Internet** (Lei 12.965/2014) | provedores guardam registros de conexão (1 ano) e de acesso a aplicações (6 meses); entregar só com ordem judicial |
| **LGPD** (Lei 13.709/2018) | IP e dados de navegação são dados pessoais; coletar exige base legal, finalidade e cuidado |
| **Lei 12.737/2012** ("Carolina Dieckmann") | invadir dispositivo alheio é crime |
| **Lei 9.296/1996** | interceptar comunicação sem ordem judicial é crime |
| **CPP, arts. 158-A a 158-F** | cadeia de custódia |
| **CPP, art. 159** | perícia por perito oficial (ou dois peritos nomeados) |

Por isso tudo no Sentinela é **no próprio aparelho, ou em rede com autorização e consentimento**.

---

## Exercícios

1. Monte uma cadeia de custódia (uma tabela) para uma sessão do Sentinela capturada no seu celular.
2. Por que se analisa a cópia e não o original?
3. Um log mostra um acesso às 14:03 e o pcap mostra a conexão às 17:03. O que provavelmente
   aconteceu, e como o laudo deve tratar isso?
4. Um ataque veio do IP 177.x.x.x de uma operadora brasileira. O que é preciso para chegar ao
   cliente? O que isso não prova?
5. Escreva os quesitos (perguntas) de um laudo sobre "um app do celular está enviando dados para
   servidores de rastreamento?".

### Respostas

1. Colunas: item (arquivo `.pcap`), hash SHA-256, data e hora (UTC) da coleta, quem coletou, com
   que ferramenta e versão, onde foi guardado, e cada acesso posterior (quem, quando, para quê).
2. Qualquer exame pode alterar o material (até abrir um arquivo muda metadados). A cópia
   verificada por hash pode ser refeita; o original não.
3. Diferença de exatos 3 horas: um dos registros está em UTC e o outro em horário de Brasília
   (UTC−3). O laudo deve normalizar tudo para UTC e explicar a conversão.
4. IP + porta de origem + data e hora exatas (por causa do CGNAT), e um pedido judicial à
   operadora. Mesmo assim, prova qual **contrato de internet** foi usado, não quem estava usando.
5. Por exemplo: o app estabeleceu conexões com quais domínios, em que horários? Algum desses
   domínios consta em listas públicas de rastreadores? As conexões ocorreram com o app em uso ou
   em segundo plano? Qual o volume de dados enviado?

## Para pesquisar mais

- Sherri Davidoff e Jonathan Ham, *Network Forensics: Tracking Hackers through Cyberspace*.
- Richard Bejtlich, *The Practice of Network Security Monitoring*.
- Jesus Antonio Velho (org.), *Tratado de Computação Forense* (referência brasileira).
- RFC 3227; normas ISO/IEC 27037 e 27042.
- Textos das leis em planalto.gov.br.
