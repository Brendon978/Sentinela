#!/usr/bin/env bash
# Compila e roda os testes C no PC (ASan + UBSan). Uso: tools/testes-c.sh [filtro]
set -euo pipefail
raiz="$(cd "$(dirname "$0")/.." && pwd)"
build="$raiz/native/build-host"
cmake -S "$raiz/native" -B "$build" -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON >/dev/null
cmake --build "$build" >/tmp/sn-build.log 2>&1 || { cat /tmp/sn-build.log; exit 1; }
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=print_stacktrace=1 \
    "$build/testes" "${1:-}"
