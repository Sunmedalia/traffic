#!/usr/bin/env bash
set -euo pipefail
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = aarch64 ] || { echo 'Validated target is ARM64 Linux' >&2; exit 1; }
project_dir=$(cd "$(dirname "$0")/.." && pwd)
build_dir=${1:?Usage: build-ecapture.sh NEW_BUILD_DIRECTORY}
[ ! -e "$build_dir" ] || { echo 'Use a new build directory' >&2; exit 1; }
git clone --depth 1 --branch v2.9.1 https://github.com/gojue/ecapture.git "$build_dir"
cd "$build_dir"
[ "$(git rev-parse HEAD)" = 143e771cf2b4919aedc27fd7b4b24ff87b8725b9 ]
git apply "$project_dir/patches/ecapture-v2.9.1-connection-cache.patch"
# This release bundle targets the test site's OpenSSL 3.5 CO-RE probe.
make core TARGETS=openssl_3_5_0 PARALLEL=1
mkdir -p "$project_dir/bin"
cp bin/ecapture "$project_dir/bin/ecapture"
cp LICENSE "$project_dir/bin/ecapture.LICENSE"
sha256sum "$project_dir/bin/ecapture" > "$project_dir/bin/ecapture.SHA256SUMS"
