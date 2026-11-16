# Aula 7 — Segurança da informação

Os conceitos e o vocabulário da área. É o que a banca e o artigo esperam que você domine.

---

## 1. A tríade CIA

| pilar | pergunta | ataque típico | defesa típica |
|---|---|---|---|
| **C**onfidencialidade | só quem deve consegue ler? | interceptação, vazamento | criptografia, controle de acesso |
| **I**ntegridade | o dado está como deveria? | alteração, adulteração | hash, assinatura digital |
| **D**isponibilidade | está funcionando quando precisa? | DoS, ransomware | redundância, backup |

Alguns autores somam **autenticidade** (quem diz ser, é) e **não repúdio** (quem fez não pode negar).
Para forense, integridade é o pilar central: evidência sem integridade não vale.

## 2. Ameaça, vulnerabilidade e risco

- **Vulnerabilidade:** a fraqueza (um campo que não trata SQL injection, uma senha fraca).
- **Ameaça:** quem ou o que pode explorar (um atacante, um malware).
- **Risco:** a chance de a ameaça explorar a vulnerabilidade, vezes o estrago.
- **Superfície de ataque:** tudo que está exposto (portas abertas, formulários, apps, pessoas).

## 3. Ataques comuns

| ataque | o que é | rastro na rede |
|---|---|---|
| **Varredura** (scan) | mapear portas e serviços | muitos SYN para portas diferentes, muitos RST |
| **Força bruta** | tentar senhas em série | muitas conexões curtas no SSH/login |
| **Phishing** | enganar a pessoa (e-mail, SMS, site falso) | domínios parecidos, recém-registrados |
| **MITM** | ficar no meio da conversa (ARP spoofing, Wi-Fi falso) | MAC duplicado, certificado estranho |
| **DoS/DDoS** | derrubar por excesso | volume anormal, muitas origens |
| **SQL injection** | enfiar SQL num campo para o banco executar | `' OR 1=1 --` no corpo do HTTP (se não for HTTPS) e no log da aplicação |
| **XSS** | enfiar script numa página para rodar no navegador de outra pessoa | `<script>` em parâmetros |
| **C2** (comando e controle) | máquina infectada falando com o atacante | conexões em intervalos regulares (*beaconing*), DNS esquisito |
| **Exfiltração** | levar dados para fora | upload grande e incomum, DNS com nomes enormes (túnel DNS) |

Repare na última coluna: é tudo **metadado**. Esse é o argumento do artigo.

### SQL injection em 30 segundos

```sql
-- o código faz: "SELECT * FROM usuarios WHERE nome = '" + entrada + "'"
-- o atacante digita:   ' OR '1'='1
SELECT * FROM usuarios WHERE nome = '' OR '1'='1'   -- devolve todos
```

A defesa é **consulta parametrizada**: a entrada vai como dado, nunca como pedaço do SQL. É o
"tratado como texto" que você comentou. Treine no **DVWA**, num laboratório seu.

## 4. Defesa em camadas

Nenhuma barreira é perfeita, então se empilham várias:

| camada | ferramenta | faz |
|---|---|---|
| perímetro | **firewall** | bloqueia por IP/porta |
| aplicação web | **WAF** | barra SQLi, XSS e afins no HTTP |
| rede | **IDS** / **IPS** | detecta (IDS) ou detecta e bloqueia (IPS) ataques no tráfego |
| máquina | **antivírus / EDR** | vigia processos e arquivos de cada computador |
| centralização | **SIEM** | junta e correlaciona os logs de tudo |
| resposta | **SOAR** | automatiza a reação (bloquear IP, isolar máquina) |
| pessoas | **SOC** | a equipe que olha os alertas 24 horas |

IDS por **assinatura** (Suricata) pega ataques conhecidos. IDS por **anomalia** (o foco do seu
artigo) pega o que foge do normal, inclusive ataques novos, mas gera mais alarme falso.

## 5. Criptografia na prática

- **Hash** (SHA-256): impressão digital de um dado. Mesmo dado → mesmo hash; muda 1 bit → hash
  totalmente diferente; não dá para voltar do hash ao dado. Uso: integridade e senhas
  (com *salt* e algoritmos lentos, como bcrypt e Argon2). MD5 e SHA-1 estão quebrados para
  segurança.
- **Simétrica** (AES, ChaCha20): uma chave cifra e decifra. Rápida.
- **Assimétrica** (RSA, curvas elípticas): par de chaves pública e privada. Usada para combinar
  chaves e para **assinar**.
- **Certificado:** "esta chave pública é deste domínio", assinado por uma autoridade
  certificadora. É o que o navegador confere no TLS.

## 6. Frameworks que a área usa

- **MITRE ATT&CK** (attack.mitre.org): catálogo das táticas e técnicas de atacantes reais, com
  códigos (ex.: T1046 = varredura de serviços de rede). Artigos de detecção costumam dizer quais
  técnicas cobrem.
- **Cyber Kill Chain** (Lockheed Martin): as fases de um ataque, do reconhecimento à ação final.
  Detectar cedo (no reconhecimento) é o seu ponto sobre "a tentativa que falhou também é informação".
- **OWASP Top 10** (owasp.org): as falhas mais comuns em aplicações web.

---

## Exercícios

1. Classifique em C, I ou D: ransomware; alguém lendo seu Wi-Fi aberto; troca de valor num boleto.
2. Qual a diferença entre IDS e IPS? Por que IPS precisa de mais cuidado com falso positivo?
3. Escreva a versão parametrizada de `"SELECT * FROM u WHERE nome = '" + nome + "'"` em C# (ADO.NET).
4. Ache no MITRE ATT&CK o código de "Brute Force" e de "Application Layer Protocol: DNS".
5. Por que um alerta de "beaconing" (conexões a cada 60 s exatos) é suspeito?

### Respostas

1. D (e às vezes C, quando vazam os dados); C; I.
2. O IDS só avisa; o IPS bloqueia. Um falso positivo no IPS derruba usuário legítimo.
3. `cmd.CommandText = "SELECT * FROM u WHERE nome = @nome"; cmd.Parameters.AddWithValue("@nome", nome);`
4. T1110 e T1071.004.
5. Gente não navega com relógio. Intervalo regular sugere um programa automático "ligando para
   casa", típico de malware falando com o servidor de comando e controle. (Atualizações e
   sincronizações também fazem isso, e aí entra a triagem do analista.)

## Para pesquisar mais

- **TryHackMe**: trilhas "Pre Security" e "SOC Level 1" (muitas salas gratuitas).
- OWASP Top 10 e o **DVWA** (Damn Vulnerable Web Application) para praticar em laboratório.
- MITRE ATT&CK, especialmente a matriz "Enterprise".
- Guia de certificação CompTIA Security+ (bom mapa geral, mesmo sem fazer a prova).
