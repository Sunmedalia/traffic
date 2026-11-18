#!/usr/bin/env bash
set -euo pipefail
[ "$(uname -s)" = Linux ] || { echo 'Build on Linux' >&2; exit 1; }
case "$(uname -m)" in
  aarch64|x86_64) ;;
  *) echo 'Supported targets are ARM64 and x86_64 Linux' >&2; exit 1 ;;
esac
project_dir=$(cd "$(dirname "$0")/.." && pwd)
build_dir=${1:?Usage: build-ecapture.sh NEW_BUILD_DIRECTORY}
[ ! -e "$build_dir" ] || { echo 'Use a new build directory' >&2; exit 1; }
git clone --depth 1 --branch v2.9.1 https://github.com/gojue/ecapture.git "$build_dir"
cd "$build_dir"
[ "$(git rev-parse HEAD)" = 143e771cf2b4919aedc27fd7b4b24ff87b8725b9 ]
git apply --recount "$project_dir/patches/ecapture-v2.9.1-connection-cache.patch"
git apply "$project_dir/patches/ecapture-v2.9.1-discard-text.patch"
git apply "$project_dir/patches/ecapture-v2.9.1-queue-budget.patch"
git apply "$project_dir/patches/ecapture-v2.9.1-compact-events.patch"
git apply "$project_dir/patches/ecapture-v2.9.1-ready.patch"
git apply "$project_dir/patches/ecapture-v2.9.1-kernel-scope.patch"
git apply "$project_dir/patches/ecapture-v2.9.1-owned-payload.patch"
git apply "$project_dir/patches/ecapture-v2.9.1-reorder-heap.patch"
git apply "$project_dir/patches/ecapture-v2.9.1-drain.patch"
# Build all four upstream 1.1.1 ABI groups together with OpenSSL 3.0/3.5.
make core TARGETS="openssl_1_1_1a openssl_1_1_1b openssl_1_1_1d openssl_1_1_1j openssl_3_0_0 openssl_3_0_12 openssl_3_5_0" PARALLEL=1
mkdir -p "$project_dir/bin"
cp bin/ecapture "$project_dir/bin/ecapture"
cp LICENSE "$project_dir/bin/ecapture.LICENSE"
sha256sum "$project_dir/bin/ecapture" > "$project_dir/bin/ecapture.SHA256SUMS"

python3 - "$project_dir/bin/ecapture" "$project_dir" <<'PYMETA'
import hashlib,json,platform,sys
from pathlib import Path
binary=Path(sys.argv[1])
metadata={"schema_version":1,"source_commit":"143e771cf2b4919aedc27fd7b4b24ff87b8725b9","arch":platform.machine(),"sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),"openssl_abis":["1.1.1","3.0","3.5"]}
metadata["patch_sha256"]={patch.name:hashlib.sha256(patch.read_bytes()).hexdigest() for patch in sorted((Path(sys.argv[2])/"patches").glob("ecapture-v2.9.1-*.patch"))}
metadata["features"]=["pid_scope_v1","ready_v1","compact_tls_v2","bounded_output_v1","drain_v1"]
Path(str(binary)+".traffic.json").write_text(json.dumps(metadata,indent=2)+"\n",encoding="utf-8")
PYMETA
