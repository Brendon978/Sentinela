# Aula 11 — Pesquisa e escrita acadêmica

Para transformar o Sentinela em artigo, e o artigo em porta de entrada para o mestrado.

---

## 1. Como ler um artigo sem sofrer

Não leia do começo ao fim de primeira. Em três passadas:

1. **5 minutos:** título, resumo, figuras e conclusão. Serve para mim?
2. **30 minutos:** introdução, método e resultados, pulando a matemática pesada. Anote: problema,
   método, dados, resultado, limitação.
3. **Leitura completa:** só dos artigos centrais para o seu trabalho.

Mantenha uma planilha (ou o Zotero) com: referência, problema, método, dataset, resultado,
limitação e "como se relaciona com o meu".

## 2. Onde buscar

- **Google Acadêmico** (scholar.google.com): o ponto de partida. Use "citado por" para achar
  trabalhos mais novos sobre o mesmo assunto.
- **Portal de Periódicos CAPES:** acesso a bases pagas (IEEE, ACM, Elsevier). Como egresso, veja
  com a biblioteca se ainda tem acesso; alguns artigos também estão livres no arXiv.
- **IEEE Xplore** e **ACM Digital Library:** as grandes da computação.
- **SBSeg** (Simpósio Brasileiro de Segurança da Informação, da SBC): os anais estão abertos na
  SBC OpenLib. Ótimo para ver o que se pesquisa no Brasil e quem orienta o quê.
- Termos de busca úteis: *network forensics*, *intrusion detection machine learning*,
  *anomaly detection network flow*, *mobile traffic analysis*, *forensic readiness*.

## 3. A estrutura de um artigo

| seção | responde |
|---|---|
| Resumo / Abstract | tudo em ~200 palavras: problema, método, resultado |
| Introdução | por que importa, qual a lacuna, qual a sua contribuição |
| Fundamentação / Trabalhos relacionados | o que já existe e onde o seu se encaixa |
| Metodologia | como foi feito, em detalhe suficiente para repetir |
| Resultados | o que saiu (tabelas, gráficos, métricas) |
| Discussão | o que os resultados significam e suas **limitações** |
| Conclusão | resposta à pergunta e trabalhos futuros |
| Referências | ABNT (ou o padrão da revista) |

Para o seu: a **contribuição** é a ferramenta de baixo custo com coleta íntegra mais a comparação
regras × IA na triagem. As **limitações** honestas (sem root, HTTPS cifrado, dados de laboratório)
contam a favor, não contra.

## 4. Citação e referências

- Use um gerenciador: **Zotero** (gratuito). Ele captura a referência pelo navegador e formata em
  ABNT sozinho.
- Toda afirmação que não é sua precisa de fonte. Copiar sem citar é plágio, inclusive o próprio
  texto já publicado.
- Prefira fontes primárias (o artigo original do dataset, a RFC) a resumos de blog.

## 5. Ética em pesquisa

- Dados de pessoas (tráfego dos amigos) → **termo de consentimento** escrito, explicando o que é
  coletado, para quê e como será protegido.
- **Anonimização** antes de publicar: troque IPs, MACs, nomes de aparelhos e domínios pessoais.
- Pergunte à faculdade se o trabalho precisa passar pelo **CEP** (Comitê de Ética em Pesquisa).
  No Brasil, pesquisas com dados de pessoas seguem as resoluções do CNS (em ciências humanas e
  sociais, a Resolução 510/2016).
- Laboratório virtual e datasets públicos evitam boa parte desses problemas: por isso os números
  principais do artigo saem deles.

## 6. Escolhendo o mestrado

- Procure programas com linha de **segurança** ou **forense**. Veja na Plataforma Sucupira (CAPES)
  as linhas de pesquisa e as notas dos programas.
- Mais importante que o programa é o **orientador**: leia os artigos dos professores da linha. Se
  o seu tema conversa com o que ele publica, a chance aumenta muito.
- Mestrado **acadêmico** (foco em pesquisa, costuma ter bolsa) x **profissional** (foco aplicado,
  muito procurado por quem trabalha, como peritos). Os dois servem.
- Mande um e-mail curto ao possível orientador com: quem você é, o artigo publicado e a ideia de
  pesquisa em um parágrafo.

---

## Exercícios

1. Ache no Google Acadêmico três artigos com "network forensics" e "machine learning" dos últimos
   cinco anos e preencha a planilha do item 1.
2. Ache nos anais do SBSeg um artigo sobre detecção de intrusão e anote quem são os autores e de
   que universidade.
3. Escreva a sua pergunta de pesquisa numa frase e a contribuição em outra.
4. Liste três limitações do Sentinela que o artigo deve declarar.

### Respostas (sugestões)

3. Pergunta: "É possível realizar a triagem forense de tráfego de rede com apoio de aprendizado de
   máquina usando apenas metadados de fluxo coletados por uma ferramenta de baixo custo?"
   Contribuição: "Uma ferramenta aberta que coleta tráfego com garantia de integridade e uma
   comparação entre regras fixas e detecção de anomalias na triagem."
4. Não vê conteúdo de HTTPS; no celular, só vê o próprio tráfego (sem root); os ataques avaliados
   vêm de laboratório e de datasets, que podem não representar todo ataque real.

## Para pesquisar mais

- Antônio Joaquim Severino, *Metodologia do Trabalho Científico*.
- Guia de normalização (ABNT) da biblioteca da sua faculdade.
- zotero.org; Plataforma Sucupira (sucupira.capes.gov.br); SBC OpenLib (sol.sbc.org.br).
