#!/usr/bin/env bash
# Mostra como o Wireshark (tshark) disseca uma fixture: é daqui que saem os valores
# esperados dos testes. Uso: tools/fixtures/oraculo.sh v4_udp_simples
set -euo pipefail
raiz="$(cd "$(dirname "$0")/../.." && pwd)"
command -v tshark >/dev/null || { echo "falta o tshark: sudo pacman -S wireshark-cli" >&2; exit 2; }
tshark -r "$raiz/native/tests/fixtures/$1.pcap" -V -o ip.check_checksum:TRUE \
    -o udp.check_checksum:TRUE -o tcp.check_checksum:TRUE
