#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
version=${1:?version}
arch=${2:?arch}
root=$(mktemp -d)
# Containers create private, root-owned evidence directories.
trap 'sudo rm -rf "$root"' EXIT
for distro in ubuntu centos7; do
  for component in traffic traffic-console; do
    tar -xzf "dist/$component-$version-$distro-$arch.tar.gz" -C "$root"
  done
  case "$distro" in
    ubuntu) image=ubuntu:22.04 ;;
    centos7)
      if [ "$arch" = arm64 ]; then image=arm64v8/centos:7; else image=quay.io/centos/centos:7; fi
      ;;
  esac
  # No apt/yum or capture-library installation is allowed in this smoke test.
  docker run --rm --network host --cap-add NET_ADMIN --cap-add NET_RAW \
    -v "$root:/portable" -e APP="/portable/traffic-$version-$distro-$arch" \
    -e CONSOLE="/portable/traffic-console-$version-$distro-$arch" "$image" bash -ec '
      cd /tmp
      "$APP/traffic" --cn-help
      "$APP/traffic" doctor
      "$CONSOLE/traffic-console" --help
      "$APP/deps/ecapture/ecapture" --help >/dev/null
      test -s "$APP/deps/java/traffic-java-agent.jar"
      # Verify the preload loader against the host glibc, including CentOS 7.
      LD_PRELOAD="$APP/libtraffic-openssl.so" /bin/true
      "$APP/traffic" capture --no-tls --ports 18764 --duration 2s --name release-smoke
      test -n "$(find "$APP/sessions" -name index.sqlite -print -quit)"
    '
done
