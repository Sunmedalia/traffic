#!/usr/bin/env bash
set -euo pipefail
[ "$(uname -s)" = Linux ] || { echo 'Build on Linux' >&2; exit 1; }
project_dir=$(cd "$(dirname "$0")/.." && pwd)
output=${1:-"$project_dir/bin/libtraffic-openssl.so"}
mkdir -p "$(dirname "$output")"
"${CC:-cc}" -std=gnu11 -O2 -g -Wall -Wextra -Werror -fPIC -shared \
  -Wl,-z,relro,-z,now -o "$output" "$project_dir/native/openssl-preload/traffic_openssl.c" -ldl -lpthread
