#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
# usage: compile.sh AWSLC_PREFIX OUTPUT_FILE
# AWSLC_PREFIX is the install folder of an AWS-LC build (it holds include/ and lib/libcrypto.a).
set -eu
[ $# -eq 2 ] || { echo "usage: compile.sh AWSLC_PREFIX OUTPUT_FILE" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
exec gcc -O2 -Wall -I "$1/include" "$here/verify.c" -o "$2" "$1/lib/libcrypto.a" -lpthread -ldl
