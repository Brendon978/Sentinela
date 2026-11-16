# Aula 4 — Redes: o caminho de um pacote

Quando você abre um site no celular, o que acontece até a página aparecer? Esta aula segue esse
caminho camada por camada. É a aula mais importante para o projeto.

---

## 1. Camadas e encapsulamento

Cada camada resolve um problema e confia na de baixo. Na ida, cada uma **embrulha** o que recebeu
com o seu próprio cabeçalho; na volta, cada uma tira o seu.

| camada (TCP/IP) | OSI | resolve | exemplo | endereço |
|---|---|---|---|---|
| Aplicação | 7, 6, 5 | o que o programa quer dizer | HTTP, DNS, TLS | nome (`exemplo.com`) |
| Transporte | 4 | qual programa, e entrega confiável ou não | TCP, UDP | porta |
| Rede (Internet) | 3 | chegar a outra rede, pelo mundo | IPv4, IPv6 | IP |
| Enlace | 2 | chegar ao vizinho do mesmo cabo/Wi-Fi | Ethernet, Wi-Fi | MAC |
| Física | 1 | bits viram sinal | cabo, rádio | — |

```
[ Ethernet | IP | TCP | TLS | HTTP: "GET /" ]
   enlace   rede transp.  aplicação
```

O tun do Android entrega ao Sentinela os pacotes **a partir do IP** (sem Ethernet). Por isso o
`.pcap` usa o tipo "Raw IP".

---

## 2. Enlace: MAC, ARP e switch

- **MAC:** endereço de 48 bits gravado na placa de rede, escrito como `20:7c:14:f7:0f:69`. Os 3
  primeiros bytes identificam o fabricante (o OUI). Só tem sentido **dentro da rede local**.
- **Switch:** aprende em que porta está cada MAC e entrega o quadro só para ela.
- **ARP:** "quem tem o IP 192.168.77.1? Me diga o seu MAC". É uma pergunta em *broadcast* (para
  todos). Ninguém confere a resposta, e por isso o **ARP spoofing** funciona: um atacante responde
  "sou eu" e passa a receber o tráfego dos outros (um ataque *man-in-the-middle*). Um IDS de rede
  detecta isso vendo dois MACs dizendo ter o mesmo IP.

No Wi-Fi a ideia é a mesma, com o ponto de acesso no papel do switch.

---

## 3. Rede: IPv4

Endereço de 32 bits, escrito em 4 bytes decimais: `192.168.77.22`.

### Máscara e CIDR

`192.168.77.0/24` quer dizer: os primeiros **24 bits** identificam a rede e os 8 restantes, o
aparelho. Máscara `/24` = `255.255.255.0`. Cabem 256 endereços (o `.0` é a rede e o `.255` é o
broadcast, então 254 sobram para aparelhos).

Para saber se dois IPs estão na mesma rede: `IP & máscara` dos dois dá o mesmo resultado?
(Olha o AND da aula 1 aparecendo.)

### Roteamento

Se o destino está na mesma rede, entrega direto. Senão, manda para o **gateway padrão** (o
roteador), que repassa para o próximo, e assim por diante. O campo **TTL** começa em 64 ou 128 e
cada roteador tira 1; chegou a 0, o pacote morre (isso evita loops). O `traceroute` usa isso para
descobrir o caminho.

### O cabeçalho IPv4 (RFC 791)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------+-------+---------------+-------------------------------+
|Versão |  IHL  |  DSCP/ECN     |        Tamanho total          |  bytes 0-3
+-------+-------+---------------+-----+-------------------------+
|        Identificação          |Flags|  Deslocamento (offset)  |  bytes 4-7
+---------------+---------------+-----+-------------------------+
|      TTL      |   Protocolo   |     Checksum do cabeçalho     |  bytes 8-11
+---------------+---------------+-------------------------------+
|                       Endereço de origem                      |  bytes 12-15
+---------------------------------------------------------------+
|                       Endereço de destino                     |  bytes 16-19
+---------------------------------------------------------------+
|                    Opções (se IHL > 5)                        |
+---------------------------------------------------------------+
```

Protocolo: **6 = TCP, 17 = UDP, 1 = ICMP**.

Exemplo real (fixture `v4_udp_simples`):

```
45 00 00 1e 12 34 00 00 40 11 5c 2a 0a 6f 00 01 01 01 01 01 ...
│  │  └─┬─┘ └─┬─┘ └─┬─┘ │  │  └─┬─┘ └────┬────┘ └────┬────┘
│  │   30   0x1234  0   │  17  checksum 10.111.0.1   1.1.1.1
│  DSCP 0               TTL 64 (UDP)
versão 4, IHL 5 (20 bytes)
```

### Fragmentação

Se o pacote é maior que o enlace aguenta (o **MTU**, normalmente 1500 bytes), ele pode ser
quebrado em fragmentos. Hoje é raro, e fragmento estranho é usado para enganar IDS; a v1 do
Sentinela descarta.

---

## 4. IPv6

Endereço de **128 bits**, em 8 grupos de 16 bits em hex: `2606:4700:4700:0000:0000:0000:0000:1111`.
Zeros à esquerda somem e uma sequência de grupos zerados vira `::` (uma vez só):
`2606:4700:4700::1111`.

- Cabeçalho fixo de **40 bytes**, sem checksum, sem fragmentação no caminho.
- Campos principais: versão (6), tamanho do *payload*, **Next Header** (o que vem depois),
  **Hop Limit** (o TTL do IPv6), origem e destino.
- Coisas opcionais vão em **cabeçalhos de extensão** encadeados: cada um diz qual é o próximo.
- Endereços: `fe80::/10` só no enlace local; `fc00::/7` privados (o Sentinela usa `fd00:5e:1::1`);
  `ff00::/8` multicast.

As operadoras de celular brasileiras usam muito IPv6. Por isso o Sentinela precisa dele.

---

## 5. Endereços privados, NAT e CGNAT

Faixas privadas (RFC 1918), que não andam pela Internet: `10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16`. O seu `192.168.77.22` é uma delas.

O **NAT** do roteador troca o IP privado de origem pelo IP público dele na ida e desfaz na volta,
guardando uma tabela de conexões (IP, porta) ↔ (IP público, porta). Um monte de aparelhos sai com
um IP só.

O **CGNAT** é o mesmo truque feito pela **operadora**: centenas de clientes atrás de um IP público.
Consequência forense: **um IP público não identifica uma pessoa**. Para chegar a um cliente, é
preciso IP **+ porta de origem + horário exato**, e o Marco Civil obriga os provedores a guardarem
esses registros.

O Sentinela faz um "NAT" por dentro do celular: os apps falam com o tun e o motor fala com a
Internet por sockets próprios.

---

## 6. ICMP

Mensagens de controle do IP: "destino inalcançável", "TTL esgotado" e o par **echo request /
echo reply** do `ping`. Também é usado em ataques (varredura, túneis escondidos).

---

## 7. Transporte: portas, UDP e TCP

A **porta** (16 bits) diz qual programa recebe. Portas conhecidas: 22 SSH, 53 DNS, 80 HTTP, 123
NTP, 443 HTTPS, 853 DNS sobre TLS. Uma conexão é identificada pela **5-tupla**: protocolo, IP de
origem, porta de origem, IP de destino, porta de destino.

### UDP (RFC 768) — "manda e torce"

Cabeçalho de 8 bytes: porta de origem, porta de destino, tamanho, checksum. Sem conexão, sem
garantia de entrega nem de ordem. Usado por DNS, jogos, voz, vídeo e QUIC.

### TCP (RFC 9293) — "entrega garantida e em ordem"

Cabeçalho de 20 bytes ou mais. Campos-chave: portas, **número de sequência**, **número de
confirmação (ack)**, **flags** (SYN, ACK, FIN, RST, PSH), **janela**.

**Handshake de 3 vias:**

```
cliente                         servidor
   │ ── SYN, seq=100 ──────────► │   "quero conversar; começo no 100"
   │ ◄── SYN+ACK, seq=300, ack=101│   "ok; eu começo no 300; espero o seu 101"
   │ ── ACK, ack=301 ───────────► │   "combinado"
```

- **seq** conta bytes enviados; **ack** diz "recebi tudo até aqui, mande o próximo".
- O que não for confirmado é **retransmitido**.
- **Janela:** quanto o outro lado aguenta receber agora (controle de fluxo).
- **Fim:** cada lado manda **FIN** e o outro confirma (4 passos). **RST** encerra na hora ("não
  conheço essa conexão" ou "deu ruim").

Para forense e IDS: uma porta fechada responde SYN com RST. Uma **varredura de portas** é
justamente mandar SYN para muitas portas e ver quem responde SYN+ACK.

---

## 8. DNS e DHCP

**DNS** traduz nome em IP. O celular pergunta ao **resolvedor** (normalmente o roteador ou a
operadora), que pergunta à raiz, ao `.com`, ao servidor do domínio, e devolve a resposta.

| tipo | resposta |
|---|---|
| A | IPv4 |
| AAAA | IPv6 |
| CNAME | "esse nome é apelido de outro" |
| MX | servidor de e-mail |
| TXT | texto livre |

O DNS clássico vai **sem criptografia** pela porta 53 UDP: quem está no caminho vê todos os nomes
que você consulta. Por isso ele é ouro para forense, e por isso existem **DoT** (DNS sobre TLS,
porta 853) e **DoH** (DNS dentro do HTTPS). O Sentinela lê as respostas DNS para dar nome aos IPs,
e alerta quando um app foge para DoT/DoH.

**DHCP** é quem te entrega IP, máscara, gateway e DNS quando você entra numa rede.

---

## 9. HTTP, TLS e QUIC

- **HTTP** é texto: `GET /pagina HTTP/1.1`, cabeçalhos, corpo. Sem criptografia, qualquer um no
  caminho lê.
- **TLS** cria um canal criptografado em cima do TCP. No começo (o **handshake**), o cliente manda
  o **ClientHello**, que ainda vai aberto e traz a extensão **SNI** com o nome do site. O servidor
  responde com o **certificado**, que prova a identidade dele (assinado por uma autoridade
  certificadora). Depois disso, tudo é cifrado.
- **HTTPS** = HTTP dentro do TLS, porta 443.
- **QUIC** (HTTP/3) faz o papel do TCP+TLS em cima do **UDP**, porta 443. É mais difícil de
  observar.

O que dá para ver no HTTPS sem quebrar a criptografia: IP, porta, nome (DNS e SNI), horários,
tamanhos e ritmo dos pacotes. São esses **metadados** que o artigo usa.

---

## 10. Wi-Fi

- Padrão **802.11**. O ponto de acesso anuncia a rede com **beacons**; os aparelhos procuram com
  **probe requests** (que revelam redes que o aparelho já conheceu).
- **WPA2/WPA3** criptografam o rádio. No WPA2-Personal, quem sabe a senha e captura o "aperto de
  mão" (*4-way handshake*) de um aparelho consegue decifrar o tráfego dele.
- **Modo monitor:** a placa capta todos os quadros do ar, não só os seus.
- Ataques que um IDS de Wi-Fi detecta: **deauth** (quadros falsos que derrubam conexões),
  **evil twin** (ponto de acesso falso com o mesmo nome).

---

## Exercícios

1. `10.111.0.1` e `10.111.0.200` estão na mesma rede `/24`? E na mesma `/25`?
2. Quantos endereços tem uma rede `/22`?
3. Abra `native/tests/fixtures/v4_com_opcoes.pcap` com `tshark -V -r`. Qual é o tamanho do
   cabeçalho IP e por quê? Quais flags TCP estão ligadas?
4. Rode `dig +trace wikipedia.org` e descreva o caminho da consulta.
5. Por que um ataque de varredura de portas em TCP gera muitos RST?
6. Escreva `2001:0db8:0000:0000:0000:ff00:0042:8329` na forma curta.
7. Por que, no HTTPS, o SNI ainda vai aberto? O que o ECH (Encrypted Client Hello) muda?

### Respostas

1. Na `/24` sim (os 3 primeiros bytes são iguais). Na `/25`, não: a `/25` divide o último byte em
   0–127 e 128–255, e o `.1` e o `.200` caem em metades diferentes.
2. 2¹⁰ = 1024 (32 − 22 = 10 bits para aparelhos).
3. 24 bytes: IHL = 6, porque tem 4 bytes de opções (NOP). Só a SYN.
4. Vai da raiz (`.`) aos servidores do `.org` e depois aos da Wikipédia, que dão a resposta final.
5. Cada SYN enviado a uma porta fechada recebe um RST de volta. Muitos RST seguidos, do mesmo
   destino para a mesma origem, em portas diferentes, é a assinatura de uma varredura.
6. `2001:db8::ff00:42:8329`.
7. O servidor precisa saber qual certificado mandar antes de existir uma chave combinada. O ECH
   cifra o ClientHello com uma chave publicada no DNS do site, escondendo o SNI. Quando ele se
   espalhar, o domínio vai ter que vir só do DNS.

## Para pesquisar mais

- Kurose & Ross, *Redes de Computadores e a Internet* (em português) — o livro-texto da área.
- W. Richard Stevens, *TCP/IP Illustrated, vol. 1*.
- **Professor Messer** (YouTube) — curso gratuito do Network+.
- RFCs: 791 (IPv4), 8200 (IPv6), 768 (UDP), 9293 (TCP), 1035 (DNS), 8446 (TLS 1.3), 9000 (QUIC).
