package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestPreflightStrictFailure(t *testing.T) {
	if requireCaptureChecks(nil) == nil || requireCaptureChecks([]captureCheck{{Status: "unavailable"}}) == nil {
		t.Fatal("strict preflight accepted unsupported target")
	}
	if err := requireCaptureChecks([]captureCheck{{Status: "candidate"}}); err != nil {
		t.Fatal(err)
	}
}

func TestProbeCapabilitiesRequireMatchingBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ecapture")
	binary := []byte("synthetic capability fixture")
	if err := os.WriteFile(path, binary, 0700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(binary)
	metadata := fmt.Sprintf(`{"schema_version":1,"sha256":"%s","openssl_abis":["1.1.1"],"features":["pid_scope_v1"]}`, hex.EncodeToString(sum[:]))
	if err := os.WriteFile(path+".traffic.json", []byte(metadata), 0600); err != nil {
		t.Fatal(err)
	}
	if !probeCapability(path, "1.1.1") || probeCapability(path, "3.5") {
		t.Fatal("capability filtering failed")
	}
	if !probeCapability(path, "feature:pid_scope_v1") || probeCapability(path, "feature:missing") {
		t.Fatal("feature manifest filtering failed")
	}
	if err := os.WriteFile(path, []byte("replaced binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if probeCapability(path, "1.1.1") {
		t.Fatal("stale manifest accepted a replacement binary")
	}
	if probeCapability(path, "feature:pid_scope_v1") {
		t.Fatal("stale manifest enabled kernel filtering for a replacement binary")
	}
}

func TestOpenSSL111VersionIdentification(t *testing.T) {
	for text, want := range map[string]bool{"OpenSSL 1.1.1w 11 Sep 2023": true, "OpenSSL 1.1.1a vendor": true, "OpenSSL 1.1.0l": false, "OpenSSL 1.1.1 without an ABI suffix": false, "OpenSSL 1.1.1x vendor": false} {
		if openssl111Version.MatchString(text) != want {
			t.Fatal("wrong ABI classification", text)
		}
	}
}
