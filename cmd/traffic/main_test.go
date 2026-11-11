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
