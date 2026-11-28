#!/usr/bin/env bash
# Apply the bundled patches to the pinned upstream before testing their output path.
set -euo pipefail
[ "$(uname -s)" = Linux ] || { echo 'Test on Linux' >&2; exit 1; }
case "$(uname -m)" in
  aarch64|x86_64) ;;
  *) echo 'Supported test hosts are ARM64 and x86_64 Linux' >&2; exit 1 ;;
esac
project_dir=$(cd "$(dirname "$0")/.." && pwd)
build_dir=${1:?Usage: test-ecapture-patches.sh NEW_BUILD_DIRECTORY}
[ ! -e "$build_dir" ] || { echo 'Use a new test directory' >&2; exit 1; }
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
git apply "$project_dir/patches/ecapture-v2.9.1-overload-recovery.patch"
git apply "$project_dir/patches/ecapture-v2.9.1-private-eventq.patch"
git apply "$project_dir/patches/ecapture-v2.9.1-pid-attach.patch"
go test -race ./internal/probe/base ./internal/probe/base/handlers ./internal/output/writers ./pkg/ecaptureq ./internal/probe/openssl ./cli/cmd
