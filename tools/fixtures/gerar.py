#!/usr/bin/env python3
"""Gera as fixtures de pacotes dos testes C com o scapy.

Cada fixture vira dois arquivos em native/tests/fixtures/:
  <nome>.hex   bytes do pacote IP cru (o que o tun entrega), lido pelo sn_fixture()
  <nome>.pcap  o mesmo pacote num pcap Raw IP, para o tshark conferir (oraculo.sh)

Os valores esperados dos testes vêm do tshark lendo o .pcap, nunca do nosso parser.
Uso: tools/.venv/bin/python tools/fixtures/gerar.py
"""
from pathlib import Path

import ssl
import struct

from scapy.all import (DNS, DNSQR, DNSRR, IP, TCP, UDP, IPOption_NOP, IPv6,
                       IPv6ExtHdrFragment, IPv6ExtHdrHopByHop, Raw)


def client_hello(nome: str | None) -> bytes:
    """ClientHello real do OpenSSL, sem rede: o handshake roda em memória e paramos no
    primeiro pacote que o cliente quer mandar."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    entrada, saida = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(entrada, saida, server_hostname=nome)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return saida.read()


def dns_resposta(**campos) -> DNS:
    return DNS(id=0x1234, qr=1, rd=1, ra=1, **campos)

DESTINO = Path(__file__).resolve().parents[2] / "native" / "tests" / "fixtures"

# nome -> (descrição, pacote). Cada tarefa acrescenta as suas.
FIXTURES = {
    # Tarefa 1: cabeçalhos IP
    "v4_udp_simples": (
        "IPv4 + UDP 10.111.0.1:40000 -> 1.1.1.1:9999, payload 'oi'",
        IP(src="10.111.0.1", dst="1.1.1.1", id=0x1234, ttl=64) / UDP(sport=40000, dport=9999) / Raw(b"oi"),
    ),
    "v4_com_opcoes": (
        "IPv4 com 4 bytes de opções (NOP x4, IHL=6) + TCP SYN 10.111.0.1:40001 -> 93.184.215.14:443",
        IP(src="10.111.0.1", dst="93.184.215.14", id=0x0101, ttl=63, options=[IPOption_NOP()] * 4)
        / TCP(sport=40001, dport=443, flags="S", seq=1000),
    ),
    "v4_fragmento": (
        "IPv4 com More Fragments ligado (primeiro fragmento) + UDP",
        IP(src="10.111.0.1", dst="1.1.1.1", id=0x2222, flags="MF", ttl=64) / UDP(sport=40002, dport=9999) / Raw(b"x" * 16),
    ),
    "v6_udp_simples": (
        "IPv6 + UDP [fd00:5e:1::1]:40003 -> [2606:4700:4700::1111]:9999, hop limit 64, payload 'ola'",
        IPv6(src="fd00:5e:1::1", dst="2606:4700:4700::1111", hlim=64) / UDP(sport=40003, dport=9999) / Raw(b"ola"),
    ),
    "v6_hop_by_hop": (
        "IPv6 + extensão Hop-by-Hop (8 bytes) + UDP, hop limit 1",
        IPv6(src="fd00:5e:1::1", dst="ff02::16", hlim=1) / IPv6ExtHdrHopByHop() / UDP(sport=40004, dport=9999) / Raw(b"hbh"),
    ),
    "v6_fragmento": (
        "IPv6 + cabeçalho de fragmento + UDP",
        IPv6(src="fd00:5e:1::1", dst="2606:4700:4700::1111") / IPv6ExtHdrFragment(id=7, m=1)
        / UDP(sport=40005, dport=9999) / Raw(b"y" * 16),
    ),
    # Tarefa 2: UDP e TCP
    "v4_tcp_syn_mss": (
        "IPv4 + TCP SYN com MSS 1460 10.111.0.1:40010 -> 93.184.215.14:443, seq 1000",
        IP(src="10.111.0.1", dst="93.184.215.14", id=0x3333, ttl=64)
        / TCP(sport=40010, dport=443, flags="S", seq=1000, window=65535,
              options=[("MSS", 1460), ("SAckOK", b""), ("WScale", 7), ("NOP", None)]),
    ),
    "v6_tcp_ack_dados": (
        "IPv6 + TCP PSH/ACK com 5 bytes 'hello' [fd00:5e:1::1]:40011 -> [2606:4700:4700::1111]:80",
        IPv6(src="fd00:5e:1::1", dst="2606:4700:4700::1111", hlim=64)
        / TCP(sport=40011, dport=80, flags="PA", seq=0x01020304, ack=0xA0B0C0D0, window=4096)
        / Raw(b"hello"),
    ),
    # Tarefa 4: DNS e SNI (payloads embrulhados em IP/UDP ou IP/TCP para o tshark ler)
    "dns_cname_a": (
        "resposta DNS www.exemplo.com -> CNAME cdn.exemplo.net -> A 93.184.215.14 e 93.184.215.15 (sem compressão)",
        IP(src="1.1.1.1", dst="10.111.0.1") / UDP(sport=53, dport=40020)
        / dns_resposta(qd=DNSQR(qname="www.exemplo.com"),
                       an=[DNSRR(rrname="www.exemplo.com", type="CNAME", rdata="cdn.exemplo.net"),
                           DNSRR(rrname="cdn.exemplo.net", type="A", rdata="93.184.215.14"),
                           DNSRR(rrname="cdn.exemplo.net", type="A", rdata="93.184.215.15")]),
    ),
    "dns_aaaa_comprimido": (
        "resposta DNS Exemplo.COM AAAA 2606:2800:21f:cb07:6820:80da:af6b:8b2c, com compressão de nomes",
        IPv6(src="2606:4700:4700::1111", dst="fd00:5e:1::1") / UDP(sport=53, dport=40021)
        / dns_resposta(qd=DNSQR(qname="Exemplo.COM", qtype="AAAA"),
                       an=[DNSRR(rrname="Exemplo.COM", type="AAAA", rdata="2606:2800:21f:cb07:6820:80da:af6b:8b2c")]).compress(),
    ),
    "dns_consulta": (
        "consulta DNS (não é resposta) para www.exemplo.com",
        IP(src="10.111.0.1", dst="1.1.1.1") / UDP(sport=40022, dport=53)
        / DNS(id=0x4321, rd=1, qd=DNSQR(qname="www.exemplo.com")),
    ),
    "tls_client_hello_sni": (
        "ClientHello real (OpenSSL) com SNI www.exemplo.com.br, TCP 10.111.0.1:40030 -> 93.184.215.14:443",
        IP(src="10.111.0.1", dst="93.184.215.14") / TCP(sport=40030, dport=443, flags="PA", seq=1, ack=1)
        / Raw(client_hello("www.exemplo.com.br")),
    ),
    "tls_client_hello_sem_sni": (
        "ClientHello real (OpenSSL) sem SNI, TCP 10.111.0.1:40031 -> 93.184.215.14:443",
        IP(src="10.111.0.1", dst="93.184.215.14") / TCP(sport=40031, dport=443, flags="PA", seq=1, ack=1)
        / Raw(client_hello(None)),
    ),
    # Saídas esperadas do montador (sn_montar_*): mesmos campos fixos que o motor usa
    # (IPv4: id 0, DF, TTL 64; IPv6: hop limit 64; TCP sem opções salvo MSS no SYN-ACK).
    "montar_v4_udp": (
        "resposta UDP 1.1.1.1:53 -> 10.111.0.1:40000, payload 'resposta'",
        IP(src="1.1.1.1", dst="10.111.0.1", id=0, flags="DF", ttl=64)
        / UDP(sport=53, dport=40000) / Raw(b"resposta"),
    ),
    "montar_v6_udp": (
        "resposta UDP [2606:4700:4700::1111]:9999 -> [fd00:5e:1::1]:40003, payload 'ok'",
        IPv6(src="2606:4700:4700::1111", dst="fd00:5e:1::1", hlim=64) / UDP(sport=9999, dport=40003) / Raw(b"ok"),
    ),
    "montar_v4_synack": (
        "SYN-ACK 93.184.215.14:443 -> 10.111.0.1:40010, seq 5000, ack 1001, janela 65535, MSS 1460",
        IP(src="93.184.215.14", dst="10.111.0.1", id=0, flags="DF", ttl=64)
        / TCP(sport=443, dport=40010, flags="SA", seq=5000, ack=1001, window=65535, options=[("MSS", 1460)]),
    ),
    "montar_v6_dados": (
        "dados TCP [2606:4700:4700::1111]:80 -> [fd00:5e:1::1]:40011, PSH/ACK, payload 'oi mundo'",
        IPv6(src="2606:4700:4700::1111", dst="fd00:5e:1::1", hlim=64)
        / TCP(sport=80, dport=40011, flags="PA", seq=7, ack=9, window=8192) / Raw(b"oi mundo"),
    ),
}


def gravar_pcap(caminho: Path, dados: bytes) -> None:
    """pcap clássico, linktype 101 (Raw IP), um pacote com carimbo fixo."""
    cabecalho = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
    registro = struct.pack("<IIII", 1_700_000_000, 0, len(dados), len(dados))
    caminho.write_bytes(cabecalho + registro + dados)


# Tarefa 3: um pcap com vários pacotes e carimbos diferentes, para comparar byte a byte
# com o que o sn_pcap grava. (nome da fixture, segundos, microssegundos)
PCAP_TRES = [
    ("v4_udp_simples", 1_700_000_000, 1),
    ("v6_udp_simples", 1_700_000_000, 500_000),
    ("v4_tcp_syn_mss", 1_700_000_001, 0),
]


def gravar_pcap_varios(caminho: Path, registros: list[tuple[int, int, bytes]]) -> None:
    saida = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
    for seg, us, dados in registros:
        saida += struct.pack("<IIII", seg, us, len(dados), len(dados)) + dados
    caminho.write_bytes(saida)


def main() -> None:
    DESTINO.mkdir(parents=True, exist_ok=True)
    for nome, (descricao, pacote) in FIXTURES.items():
        dados = bytes(pacote)
        linhas = [dados[i : i + 16].hex(" ") for i in range(0, len(dados), 16)]
        (DESTINO / f"{nome}.hex").write_text(f"# {descricao}\n" + "\n".join(linhas) + "\n")
        gravar_pcap(DESTINO / f"{nome}.pcap", dados)
        print(f"{nome}: {len(dados)} bytes")
    registros = [(seg, us, bytes(FIXTURES[nome][1])) for nome, seg, us in PCAP_TRES]
    gravar_pcap_varios(DESTINO / "pcap_tres.pcap", registros)
    print("pcap_tres.pcap: 3 pacotes")


if __name__ == "__main__":
    main()
