# Ideia de artigo

Registrada em 2026-11-13.

**Título provisório:** "Análise de dados e a utilização da IA na prevenção de ciberataques"

**Para onde:** publicação na faculdade em que o Brendon se formou.

**Ligação com o Sentinela:** o app é a ferramenta que gera os dados do estudo. Ele captura o
tráfego do próprio celular, guarda os metadados de cada conexão (app, domínio, portas, bytes,
horários) e marca comportamento suspeito.

## Recorte sugerido (a decidir)

- **Pergunta:** dá pra detectar comportamento suspeito de apps num celular só pelos metadados do
  tráfego, sem abrir o conteúdo criptografado?
- **Comparação:** regras fixas (os alertas da v1) contra um modelo de IA que aprende o normal de
  cada app (detecção de anomalia).
- **Dados:** sessões do próprio aparelho (sem dados de terceiros), mais tráfego malicioso de
  datasets públicos ou simulado num ambiente controlado.
- **Métricas:** acertos, falsos alarmes, e o que cada abordagem detecta e deixa passar.

## Pendências

- Formato e regras da publicação na faculdade (tamanho, norma ABNT, prazo).
- Escolher o tipo de modelo e os datasets públicos.
- Ética: só tráfego próprio ou com consentimento.

## Evolução da ideia (2026-11-13)

- **Foco:** a rede inteira (empresas), não só o celular. Sensor na rede + IA sobre os metadados
  de fluxo; o app vira o console. Datasets públicos com ataques rotulados: CIC-IDS2017,
  UNSW-NB15, CTU-13.
- **Correlação entre camadas:** juntar o que chega na aplicação ou no banco (ex.: tentativa de
  SQL injection num campo de formulário, que a aplicação bem feita só trata como texto) com os
  metadados de rede da mesma origem, para montar o quadro de quem está testando o sistema e
  alertar ou bloquear. No mercado isso é WAF + IDS/IPS + SIEM + resposta automática (SOAR).
- **Cuidados:** IP não identifica a pessoa (VPN, Tor, botnet, e o CGNAT das operadoras
  brasileiras põe muitos clientes atrás do mesmo IP); bloqueio automático precisa de prazo e
  limiar; guardar IP é dado pessoal na LGPD.
- **Recorte sugerido:** o artigo fica na detecção em rede (fechado e mensurável); a correlação
  entre camadas é candidata a tema do mestrado.

## Rumo combinado (2026-11-13)

- **Alvo:** forense de rede em geral, não só celular. O celular é o laboratório portátil por
  comodidade (não precisar carregar notebook).
- **Sem gastar dinheiro:**
  - laboratório virtual no VirtualBox do PC: atacante (Kali), vítima vulnerável de propósito
    (ex.: DVWA, para SQL injection) e sensor rodando o motor em C, com Zeek/Suricata para comparar;
  - datasets públicos com ataques rotulados (CIC-IDS2017, UNSW-NB15, CTU-13) para a parte de IA;
  - Sentinela no S25 FE para o próprio tráfego e o mapa de redes autorizadas;
  - celular velho do Brendon (tela quebrada, funciona) como possível sensor com root, operado
    pelo PC com `scrcpy`; falta saber o modelo e se a depuração USB estava ligada;
  - perguntar à faculdade sobre uso do laboratório de redes/segurança como egresso.
- **Regra:** só redes próprias ou com autorização do dono (Lei 9.296/96 e Lei 12.737/2012).
- O motor em C roda igual no Android e no Linux (sensor, VM ou Raspberry no futuro).
- **Notebook do Brendon:** Dell G15 5510 (Intel 10ª geração, 8 GB RAM, GTX 1660), ainda sem Linux.
  Uso previsto: hotspot que captura o tráfego dos aparelhos autorizados, modo monitor (conferir a
  placa Wi-Fi), laboratório portátil (DVWA em contêiner por causa dos 8 GB) e a GTX 1660 para
  treinar os modelos do artigo.
- **Dados de pessoas:** testes com amigos (com permissão) validam a ferramenta; no artigo, só com
  termo de consentimento por escrito, dados anonimizados e consulta ao CEP da faculdade. Em rede
  pública, só o próprio tráfego e o dos amigos que toparam. Números principais do artigo saem do
  laboratório virtual e dos datasets públicos.

## Títulos propostos para a orientadora (2026-11-13)

1. (recomendado) Forense de rede com apoio de inteligência artificial: coleta íntegra e triagem
   automatizada de tráfego com uma ferramenta de baixo custo
2. Detecção de anomalias em tráfego de rede por aprendizado de máquina: uma abordagem forense
   baseada em metadados de fluxo
3. Sentinela: uma ferramenta portátil para coleta e análise forense de tráfego de rede com apoio
   de inteligência artificial
4. Análise de dados e inteligência artificial na prevenção de ciberataques: um estudo aplicado à
   forense de rede

## Por que não basta apreender o roteiro (justificativa, 2026-11-14)

- Roteador doméstico guarda pouco e em memória volátil: lista de aparelhos/DHCP, configuração,
  às vezes um log curto que some ao reiniciar. Não guarda histórico de tráfego nem a tabela de
  NAT depois que a conexão acaba.
- Roteador só vê IP e MAC: não sabe qual app do celular abriu a conexão.
- Não vê o que vai pelos dados móveis (4G/5G), nem por dentro de uma VPN do aparelho.
- Não preserva nada com hash e cadeia de custódia; o que não foi registrado antes do incidente
  não existe (prontidão forense).
- O próprio celular também não ajuda muito: o Android guarda o volume de dados por app
  (`netstats`), não para onde cada app se conectou.
- Lacuna que o Sentinela cobre: registro prévio, por app, em qualquer rede, com integridade e
  triagem. Para a rede inteira de uma empresa, o equivalente comercial é firewall/NGFW com log de
  fluxos, NDR ou os registros do provedor (Marco Civil).

## Resumo enviado à orientadora (2026-11-14)

> A proposta é desenvolver e avaliar uma ferramenta de baixo custo para forense de rede, capaz de
> capturar o tráfego preservando a integridade da evidência (registro em formato pcap com hash
> SHA-256 e cadeia de custódia) e de identificar a origem de cada conexão. Sobre os metadados de
> fluxo, sem acesso ao conteúdo criptografado, serão comparadas duas formas de triagem: regras
> fixas e um modelo de aprendizado de máquina para detecção de anomalias. Os testes usarão um
> laboratório virtual com ataques controlados, datasets públicos com ataques rotulados (como
> CIC-IDS2017 e UNSW-NB15) e redes reais com autorização dos responsáveis e consentimento dos
> participantes. O objetivo é medir o que cada abordagem detecta, o que deixa passar e quantos
> falsos alarmes gera, avaliando como a inteligência artificial pode apoiar o perito na análise
> de grandes volumes de tráfego.

## Posicionamento (2026-11-14)

- O Sentinela é ferramenta de **prontidão forense e resposta a incidente**: só tem valor se já
  estava gravando antes do incidente. Não é ferramenta de perícia depois do fato.
- Ordem judicial ao provedor não supre isso: o provedor de conexão guarda só os registros de
  conexão (1 ano) e é proibido de guardar o histórico de acessos; as plataformas guardam IP e
  horário dos acessos (6 meses); conteúdo só por interceptação (Lei 9.296/96), dali para frente.
- Usuários previstos: empresas (resposta a incidente), a própria vítima (stalkerware, golpe),
  peritos particulares e assistentes técnicos, pesquisadores, e a polícia em monitoramento
  autorizado dali para frente.
