#!/bin/sh
# usage: compile.sh BOTAN_PREFIX OUTPUT_FILE
# BOTAN_PREFIX is the install folder of a Botan build (it holds include/botan-3/ and lib/libbotan-3.a).
set -eu
[ $# -eq 2 ] || { echo "usage: compile.sh BOTAN_PREFIX OUTPUT_FILE" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
exec g++ -std=c++20 -O2 -Wall -I "$1/include/botan-3" "$here/verify.cpp" -o "$2" "$1/lib/libbotan-3.a" -lpthread
