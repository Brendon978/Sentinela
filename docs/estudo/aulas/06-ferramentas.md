# Aula 6 — Ferramentas de análise

Ferramentas que todo analista de rede e perito usa. Pratique sempre com capturas suas ou com
amostras públicas, e só em redes com autorização.

---

## 1. Wireshark e tshark

O **Wireshark** é a ferramenta gráfica; o **tshark** é a mesma coisa no terminal (você já tem
instalado). Os dois leem e gravam `.pcap`/`.pcapng` e dissecam centenas de protocolos.

```sh
tshark -r captura.pcap                    # resumo, uma linha por pacote
tshark -r captura.pcap -V                 # árvore completa de cada pacote
tshark -r captura.pcap -x                 # bytes em hex
tshark -r captura.pcap -Y "dns"           # filtro de exibição
tshark -r captura.pcap -T fields -e ip.src -e ip.dst -e tcp.dstport   # só alguns campos
tshark -r captura.pcap -q -z conv,tcp     # estatística de conversas
tshark -r captura.pcap -q -z io,phs       # hierarquia de protocolos
```

### Filtros de exibição (o `-Y` e a barra do Wireshark)

| filtro | mostra |
|---|---|
| `ip.addr == 1.1.1.1` | tudo de ou para esse IP |
| `tcp.port == 443` | porta 443 em qualquer lado |
| `dns.qry.name contains "google"` | consultas DNS com "google" |
| `tls.handshake.extensions_server_name` | ClientHellos com SNI |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | só os SYN iniciais (início de conexões) |
| `tcp.analysis.retransmission` | retransmissões (rede ruim?) |
| `!(arp or dns)` | tira o ruído |

No Wireshark: botão direito num pacote → **Seguir → Fluxo TCP** mostra a conversa inteira.

## 2. tcpdump e filtros de captura (BPF)

O `tcpdump` captura no terminal e é leve (roda até em roteador). Os filtros de captura (BPF) são
diferentes dos de exibição: decidem **o que gravar**.

```sh
sudo tcpdump -i wlan0 -w saida.pcap                # grava tudo da interface
sudo tcpdump -i any port 53                        # só DNS, mostrando na tela
sudo tcpdump -i eth0 'host 192.168.0.10 and tcp'   # um aparelho, só TCP
```

## 3. Formato pcap

O `.pcap` clássico é simples (o Sentinela grava assim):

```
[cabeçalho global, 24 bytes] [registro 1: cabeçalho 16 bytes + pacote] [registro 2] ...
```

- Cabeçalho global: o "número mágico" `a1 b2 c3 d4` (que também revela a ordem dos bytes), versão
  2.4, tamanho máximo do pacote e o **linktype** (1 = Ethernet, 101 = Raw IP).
- Cada registro: segundos, microssegundos, tamanho gravado, tamanho original, e os bytes.

Abra um com `xxd native/tests/fixtures/v4_udp_simples.pcap` e ache cada campo. O `.pcapng` é o
formato mais novo, com comentários e várias interfaces.

## 4. nmap

Descobre aparelhos e serviços. **Só em rede própria ou autorizada**: varredura em rede alheia pode
ser enquadrada como crime.

```sh
nmap -sn 192.168.77.0/24          # quem está vivo na rede (sem varrer portas)
nmap 192.168.77.1                 # portas mais comuns do roteador
nmap -sV -p 22,80,443 alvo        # versões dos serviços
```

Bom exercício: rode um `nmap` contra o seu PC e capture ao mesmo tempo com o tshark. Você vai ver
a varredura que um IDS precisa reconhecer.

## 5. scapy

Biblioteca Python para **montar, mandar e ler pacotes** (é o que gera as fixtures do Sentinela).

```python
from scapy.all import IP, UDP, DNS, DNSQR, rdpcap
p = IP(dst="1.1.1.1") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="exemplo.com"))
p.show()                         # mostra camada por camada
bytes(p).hex(" ")                # os bytes
for pkt in rdpcap("captura.pcap"):
    if pkt.haslayer(DNS):
        print(pkt[DNS].qd.qname)
```

Use pelo venv do projeto: `tools/.venv/bin/python`.

## 6. Zeek e Suricata

São os IDS de rede abertos mais usados, e as referências com que o Sentinela vai ser comparado.

- **Zeek:** transforma o tráfego em **logs de alto nível**: `conn.log` (cada conexão: duração,
  bytes, estado), `dns.log`, `ssl.log`, `http.log`. É a ferramenta preferida de *threat hunting*
  e forense de rede, e os seus logs são praticamente as "features" de IA da aula 10.
- **Suricata:** IDS/IPS por **assinaturas** (regras do tipo "se aparecer tal padrão, alerte").
  Usa conjuntos de regras como o Emerging Threats.

```sh
zeek -r captura.pcap            # gera os .log na pasta atual
suricata -r captura.pcap -l ./saida   # gera eve.json com os alertas
```

---

## Exercícios

1. Grave 1 minuto do seu tráfego abrindo 3 sites: `tshark -i enp30s0 -a duration:60 -w meu.pcap`
   (com sudo, ou entrando no grupo `wireshark`).
2. Nessa captura, liste os nomes consultados no DNS e os SNIs dos ClientHellos.
3. Quantas conexões TCP diferentes houve? Qual teve mais bytes?
4. Abra a amostra pública `http.cap` do wiki do Wireshark e siga o fluxo TCP do pedido HTTP.
5. Explique a diferença entre filtro de captura e filtro de exibição, e quando usar cada um.

### Respostas

2. `tshark -r meu.pcap -Y dns.flags.response==0 -T fields -e dns.qry.name | sort -u` e
   `tshark -r meu.pcap -Y tls.handshake.type==1 -T fields -e tls.handshake.extensions_server_name | sort -u`.
3. `tshark -r meu.pcap -q -z conv,tcp` (a tabela já vem ordenada por bytes).
5. O de captura (BPF) decide o que é **gravado**: o que ficou de fora se perde para sempre. Use para
   economizar disco em capturas longas. O de exibição só **esconde** na hora de analisar. Em forense,
   prefira gravar tudo e filtrar depois, porque você não sabe de antemão o que vai importar.

## Para pesquisar mais

- Chris Sanders, *Practical Packet Analysis*.
- Documentação do Wireshark (wireshark.org/docs) e amostras em wiki.wireshark.org/SampleCaptures.
- *Nmap Network Scanning* (nmap.org/book) — parte gratuita online.
- docs.zeek.org e docs.suricata.io.
