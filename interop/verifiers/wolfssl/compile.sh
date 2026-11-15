#!/bin/sh
# usage: compile.sh WOLFSSL_PREFIX OUTPUT_FILE
# WOLFSSL_PREFIX is the install folder of a wolfSSL build (it holds include/ and lib/libwolfssl.a).
set -eu
[ $# -eq 2 ] || { echo "usage: compile.sh WOLFSSL_PREFIX OUTPUT_FILE" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
exec gcc -O2 -Wall -I "$1/include" "$here/verify.c" -o "$2" "$1/lib/libwolfssl.a" -lm -lpthread
