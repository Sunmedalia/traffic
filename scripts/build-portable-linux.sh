#!/usr/bin/env bash
# Called on Ubuntu release runners after the pinned eCapture build.
set -euo pipefail
cd "$(dirname "$0")/.."
ec_source=${1:?Usage: build-portable-linux.sh ECAPTURE_SOURCE}
pcap_archive=$(find "$ec_source/.build" -name libpcap.a -print -quit)
[ -n "$pcap_archive" ] || { echo 'Missing pinned static libpcap' >&2; exit 1; }
export CGO_ENABLED=1
export CGO_CFLAGS="-O2 -I$ec_source/lib/libpcap"
export CGO_LDFLAGS="-L$(dirname "$pcap_archive") -lpcap"
for component in traffic traffic-console; do
  go build -trimpath -tags 'netgo osusergo' -ldflags="-s -w -linkmode external -extldflags '-static'" -o "bin/$component" "./cmd/$component"
  if readelf -l "bin/$component" | grep -q INTERP; then echo 'Unexpected dynamic loader' >&2; exit 1; fi
  "bin/$component" --help
 done
cp "$ec_source/lib/libpcap/LICENSE" bin/libpcap.LICENSE
# The preload library must run inside older glibc applications, so build it
# against the CentOS 7 (glibc 2.17) baseline for both distro packages.
docker run --rm -v "$PWD:/io" "quay.io/pypa/manylinux2014_$(uname -m):latest" \
  bash -c 'cd /io && CC=gcc bash scripts/build-openssl-preload.sh'
# Include the patched upstream source, build recipes and submodule source.
tar -czf bin/ecapture-source.tar.gz --exclude=.git --exclude=.build --exclude=bin \
  --exclude='.checkver*' -C "$ec_source" .
