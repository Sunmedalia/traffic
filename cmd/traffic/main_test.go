package main

import (
	"strings"
	"testing"
)

func TestCollectorCommandBoundary(t *testing.T) {
	for _, command := range []string{"tui", "status", "requests", "events", "show", "export", "analyze"} {
		err := run([]string{command})
		if err == nil || !strings.Contains(err.Error(), "traffic-tui") {
			t.Fatalf("collector accepted analysis command %q: %v", command, err)
		}
	}
	if err := run([]string{"import", "--help"}); err != nil {
		t.Fatalf("import help failed: %v", err)
	}
	if err := run([]string{"capture", "--session", "example"}); err == nil {
		t.Fatal("collector accepted analysis flag")
	}
}

func TestParsePreloadUIDs(t *testing.T) {
	if uids, err := parsePreloadUIDs(""); err != nil || uids != nil {
		t.Fatalf("empty allowlist: %v %v", uids, err)
	}
	uids, err := parsePreloadUIDs(" 33, 0,33 ")
	if err != nil || len(uids) != 2 || uids[0] != 33 || uids[1] != 0 {
		t.Fatalf("allowlist parse: %v %v", uids, err)
	}
	for _, bad := range []string{"-1", "x", "1,,2", "4294967296"} {
		if _, err := parsePreloadUIDs(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
