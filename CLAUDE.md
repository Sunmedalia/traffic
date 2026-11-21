# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`traffic` is an incident-response tool for websites. It ships as **two separate binaries that are always used as a pair**:

- `cmd/traffic`: the **collector** (`doctor`, `capture`, `import`). It runs on the target host and only saves raw evidence: rotating PCAP segments, plaintext events from TLS probes, and metadata/status files. It does **no** TCP/HTTP reassembly, indexing, rule matching or alerting. The rule is that the collector must stay cheap for the target service.
- `cmd/traffic-console`: the **analyzer** (`analyze`, the default TUI `view`, `web`, the JSON queries `status`/`requests`/`events`/`show`, `export`, `rules check`). It runs offline on a copy of the session directory and does all reconstruction and detection.

User-facing docs (README, `docs/guide.md`, VALIDATION.md, OPTIMIZATION.md, release notes) and the TUI/Web UI text are in Chinese. Each CLI has `--help` (English) and `--cn-help` (Chinese). When you change a flag, update `help.go` in that command too.

## Commands

You need Go 1.26.7+ with CGO and a C compiler, plus `libpcap-dev` (gopacket/pcap and go-sqlite3 are both cgo).

```bash
go test -race ./...                      # full suite, as CI runs it
go vet ./...
test -z "$(gofmt -l cmd internal)"       # CI formatting gate
go test -race -run TestName ./cmd/traffic-console   # one test (also ./cmd/traffic, ./internal/replay, ...)
go test -run '^$' -bench BenchmarkName ./internal/replay

go build -o bin/traffic ./cmd/traffic
go build -o bin/traffic-console ./cmd/traffic-console
./scripts/build-linux.sh                 # Linux: race tests + vet + both binaries + bin/SHA256SUMS
```

Other checks CI runs:

```bash
bash scripts/build-openssl-preload.sh && bash scripts/test-openssl-preload.sh   # native/openssl-preload C library
python3 -m unittest discover -s scripts -p 'test_*.py'
node scripts/web/test-decoder.cjs        # tests cmd/traffic-console/web/decoder.js
node scripts/windows/test-iis-plaintext.js
mvn -B -f java-agent/pom.xml verify      # Java agent, JDK 17/21
bash scripts/test-ecapture-patches.sh NEW_DIR   # applies patches/ to pinned eCapture v2.9.1 and runs its tests
```

CI (`.github/workflows/ci.yml`) also runs `go test -race` and `go vet` natively on Windows. The `scripts/verify*.py`, `scripts/linux/*` and `scripts/windows/*` scripts are acceptance tests on real machines. They need a live test site and root, and they are not part of the unit suite.

## Architecture

### Package dependency rule

- `internal/session` holds the shared session model, layout, runtime/platform helpers, HTTP message and transaction JSON types, and coverage/gap accounting. Both binaries use it.
- `internal/packetio` contains pure-Go PCAP/PCAPNG readers.
- `internal/replay` does offline reconstruction: TCP/TLS streams to HTTP/1.1 and bounded HTTP/2 (HPACK) transactions, plus probe-event parsers for eCapture, OpenSSL preload, IIS and proxy. Its entry point is `replay.Build(ctx, dir, db, Options)`.
- `internal/index` contains the SQLite driver and connection helpers.
- **The collector imports only `session` and `packetio`.** SQLite, the TCP assembler and `replay` were deliberately removed from its dependency graph. Do not add `replay` or `index` imports to `cmd/traffic`.

### Analysis pipeline (`cmd/traffic-console/analyze.go`)

1. The run refuses to start while `capture.lock` is held, which means capture is still running.
2. It builds into a hidden `.analysis-build-*.sqlite` **inside the session directory**, not in /tmp, which is often tmpfs. It runs `replay.Build`, matches rules (`rules.go` built-ins plus optional user YAML), and runs scan detection.
3. It publishes an immutable `analysis-*.sqlite` by renaming the build file, then swaps the `analysis-current.json` pointer atomically. A failed or cancelled run leaves the previous result in place. Raw evidence (PCAP, `tls/stream.jsonl`, status) is never modified.
4. `analysisEngineVersion` is hashed into the rules signature. Bump it when a change alters analysis output for the same inputs.

Legacy sessions (≤ v0.1.2) carry an `index.sqlite` written during capture. The analyzer still opens these and adds alerts without reconstructing again (`rawSession(dir)` tells the two apart). Keep this compatibility.

The TUI (`tui_*.go`, Bubble Tea v2 / lipgloss v2) and Web (`web*.go` plus `web/*.js` embedded via `go:embed`) read the same analysis result and are kept in feature parity. Filters, pages and actions should behave the same in both. The web server listens on loopback by default, uses a token in the URL, and serves only its own embedded assets under a strict CSP. Captured traffic is attacker-controlled.

### Collector capture backends (`cmd/traffic`)

There are two kinds of packet capture: libpcap on Linux (`pcap_live.go`, `packet_handle_unix.go`) and WinDivert on Windows (`packet_handle_windows.go`, `windivert_batch.go`). Optional TLS plaintext probes run as helper processes or in-target agents:

- eCapture/eBPF on Linux. This is a patched, pinned v2.9.1 build: `patches/` and `scripts/build-ecapture.sh`. The queue and backpressure code is in `ecapture_queue*.go` and `ecapture_retry.go`.
- OpenSSL `LD_PRELOAD` library on Linux (`native/openssl-preload`, `preload_linux.go`). It is built against a glibc 2.17 baseline for CentOS 7.
- Java agent attach for Tomcat NIO (`java-agent/`, `java.go`).
- Windows IIS and OpenSSL probes through Frida helpers (`scripts/windows/probe-*.py`, `*.js`, `iis_windows.go`).

Probes use sequence numbers and drain/exit confirmation (`probe_sequence.go`, `probe_health.go`, `tls.go`). Evidence goes through bounded background writers (`evidence_writer.go`). Any loss or uncertainty is written explicitly to `gaps.jsonl` / `status.json` (`gap_counts`, `drain_state`, `tls_coverage`) and never hidden. A common review point: being unable to prove completeness must show up as `unverified`/unknown, not as success.

### Platform-specific code

Files use `_linux.go` / `_windows.go` / `_unix.go` with matching `_other.go` stubs and `//go:build` tags (for example `memfs_linux.go`/`memfs_other.go` and `netns_linux.go`/`netns_other.go`). When you add a platform function, add the stub too, because CI builds and tests on both Linux and Windows.

## Conventions

- Commit subjects are plain imperative sentences without a type prefix, for example "Expire scan paths from a heap; keep only two analysis generations". Release-prep commits use `docs: prepare vX.Y.Z release`. Feature work goes through branches (`feat/…`, `fix/…`, `perf/…`) and PRs into `main`.
- VALIDATION.md and OPTIMIZATION.md record what has actually been measured on real machines. Do not mark an item as validated or "passed" because tests or CI pass.
- `rules/*.yaml`, `sessions/`, `bin/`, `dist/` and capture artifacts are gitignored.
