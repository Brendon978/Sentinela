# Aula 10 — Dados e IA para detecção

A parte de IA do artigo. Sem mistério: "IA" aqui é **aprendizado de máquina** aplicado a tabelas
de conexões.

---

## 1. Ferramentas

Python com:
- **pandas:** tabelas (como uma planilha programável);
- **matplotlib / seaborn:** gráficos;
- **scikit-learn:** os modelos e as métricas;
- **Jupyter:** caderno interativo, bom para explorar.

```python
import pandas as pd
df = pd.read_csv("conexoes.csv")
df.head()                       # primeiras linhas
df.describe()                   # resumo estatístico de cada coluna
df.groupby("app")["bytes_env"].sum().sort_values(ascending=False)   # quem mais enviou
```

## 2. Estatística mínima

- **Média** (soma / quantidade) e **mediana** (o valor do meio). Em rede, a mediana é mais
  confiável: um único download gigante puxa a média lá para cima.
- **Desvio padrão:** o quanto os valores se espalham.
- **Percentil:** o p95 de duração diz que 95% das conexões duram menos que aquilo.
- **Distribuição:** o formato dos dados num histograma. Tráfego costuma ter "cauda longa" (muita
  coisa pequena e pouca coisa enorme), e por isso é comum usar escala logarítmica.

## 3. Do pacote ao fluxo: as features

Um modelo não lê pacote. Ele lê **números** que descrevem cada conexão. Essas colunas são as
**features**, e escolhê-las bem vale mais que escolher o modelo.

| feature | ideia |
|---|---|
| duração | conexão longa demais ou curta demais |
| bytes enviados / recebidos | e a razão entre eles (upload grande é suspeito) |
| pacotes enviados / recebidos | |
| tamanho médio dos pacotes | |
| intervalo entre pacotes (média, desvio) | regularidade = beaconing |
| porta de destino, protocolo | |
| flags TCP (quantos SYN, RST, FIN) | varredura gera muito SYN e RST |
| hora do dia, tela ligada | |
| domínio novo para aquele app? | |
| nº de destinos distintos por minuto | varredura e espalhamento |

O Zeek gera várias dessas sozinho no `conn.log`, e o Sentinela guarda as suas no banco de cada sessão.

## 4. Supervisionado x não supervisionado

- **Supervisionado:** você tem dados **rotulados** ("normal" ou "ataque") e o modelo aprende a
  separar. Exemplos: Random Forest, XGBoost. Muito bom para ataques **conhecidos**; não sabe o que
  nunca viu.
- **Não supervisionado / detecção de anomalia:** o modelo aprende só o **normal** e aponta o que
  foge dele. Pega coisas novas, mas "diferente" nem sempre é "ataque" (gera falso positivo).

### Isolation Forest

Ideia: pontos estranhos são fáceis de **isolar**. O modelo corta os dados ao acaso várias vezes;
o que fica sozinho com poucos cortes é anomalia.

```python
from sklearn.ensemble import IsolationForest
modelo = IsolationForest(contamination=0.01, random_state=42)
modelo.fit(X_normal)                 # aprende só com tráfego normal
nota = modelo.decision_function(X)   # quanto menor, mais anômalo
alerta = modelo.predict(X) == -1     # -1 = anomalia
```

### Autoencoder (um passo além)

Uma rede neural aprende a **comprimir e reconstruir** o tráfego normal. Quando ela reconstrói mal
uma conexão, é porque aquilo não se parece com o que ela viu: anomalia. Aqui a sua GTX 1660 ajuda.

## 5. Métricas: como provar que funciona

A **matriz de confusão**:

| | modelo disse "ataque" | modelo disse "normal" |
|---|---|---|
| **era ataque** | VP (verdadeiro positivo) | FN (falso negativo) — **passou** |
| **era normal** | FP (falso positivo) — **alarme falso** | VN (verdadeiro negativo) |

- **Precisão** = VP / (VP + FP): dos alertas, quantos eram reais?
- **Revocação (recall)** = VP / (VP + FN): dos ataques, quantos foram pegos?
- **F1:** a média harmônica das duas.
- **Taxa de falso positivo** = FP / (FP + VN).

**Acurácia engana.** Se 99,9% do tráfego é normal, um modelo que diz sempre "normal" tem 99,9% de
acurácia e não pega nada. Em detecção de intrusão, olhe precisão, recall e falsos positivos.

Exemplo: 1.000.000 de conexões e 0,1% de falso positivo = **1.000 alarmes falsos**. O analista do
SOC não dá conta. É por isso que o artigo mede o "quantos alarmes falsos".

## 6. Armadilhas (as bancas adoram perguntar)

- **Classes desbalanceadas:** quase tudo é normal. Use as métricas certas e, se treinar
  supervisionado, técnicas de balanceamento.
- **Vazamento de dados (data leakage):** uma feature que "entrega" a resposta. Exemplo clássico: o
  IP do atacante no dataset. O modelo decora o IP e parece ótimo, mas não serve para nada no mundo
  real. Tire IPs e identificadores das features.
- **Testar no que treinou:** separe treino e teste (e, de preferência, teste em **outro dia** ou
  outro dataset).
- **Datasets antigos ou artificiais:** alguns datasets famosos têm erros conhecidos de rotulagem.
  Leia os artigos que os criticam e cite.

## 7. Datasets públicos

| dataset | origem | |
|---|---|---|
| **CIC-IDS2017** | Univ. de New Brunswick (Canadá) | 5 dias de tráfego com ataques (força bruta, DoS, web, botnet); muito usado |
| **CSE-CIC-IDS2018** | mesmo grupo, em nuvem AWS | maior |
| **UNSW-NB15** | UNSW Canberra (Austrália) | 9 famílias de ataque |
| **CTU-13** | Univ. Técnica Tcheca | botnets reais misturadas com tráfego normal |

O CIC-IDS2017 já vem com as features de fluxo extraídas (pela ferramenta CICFlowMeter).

---

## Exercícios

1. Um modelo gerou 80 VP, 20 FN, 40 FP e 9.860 VN. Calcule precisão, recall e taxa de falso positivo.
2. Por que usar mediana e não média para "bytes por conexão"?
3. Se o modelo usa a porta de origem como feature, qual o problema?
4. Por que treinar o Isolation Forest só com tráfego normal?
5. Que feature você criaria para pegar uma varredura de portas?

### Respostas

1. Precisão = 80/120 ≈ 0,67; recall = 80/100 = 0,80; FPR = 40/9.900 ≈ 0,4%.
2. Poucos downloads enormes distorcem a média; a mediana representa a conexão típica.
3. A porta de origem é quase aleatória (o sistema escolhe). O modelo pode "decorar" portas do
   dataset e não generalizar. É um risco de vazamento.
4. Porque a ideia é aprender o "normal" e apontar o resto; se o ataque entra no treino, o modelo
   passa a achar o ataque normal.
5. Número de portas de destino distintas por origem num intervalo curto (ex.: por minuto), e a
   proporção de conexões que terminaram em RST.

## Para pesquisar mais

- **Machine Learning Crash Course** do Google (gratuito, tem em português).
- Aurélien Géron, *Mãos à Obra: Aprendizado de Máquina com Scikit-Learn, Keras & TensorFlow*.
- Documentação do scikit-learn (seção "Novelty and Outlier Detection").
- Artigos originais do CIC-IDS2017 (Sharafaldin et al., 2018) e do UNSW-NB15 (Moustafa e Slay, 2015).
