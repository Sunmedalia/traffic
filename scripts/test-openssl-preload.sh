#!/usr/bin/env bash
set -euo pipefail
[ "$(uname -s)" = Linux ] || { echo 'Run on Linux' >&2; exit 1; }
project_dir=$(cd "$(dirname "$0")/.." && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
"${CC:-cc}" -std=gnu11 -O2 -g -Wall -Wextra -Werror \
  -o "$test_dir/queue-test" "$project_dir/native/openssl-preload/queue_test.c" -ldl -lpthread
"$test_dir/queue-test"
