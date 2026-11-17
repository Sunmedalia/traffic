package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAnalysisCommandBoundary(t *testing.T) {
	for _, command := range []string{"capture", "doctor", "import", "rules"} {
		err := run([]string{command})
		if err == nil || !strings.Contains(err.Error(), "use traffic") {
			t.Fatalf("analyst accepted collector command %q: %v", command, err)
		}
	}
	if err := run([]string{"--help"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--interfaces", "lo"}); err == nil {
		t.Fatal("analyst accepted capture flags")
	}
}
func TestAnalysisSessionIsReadOnly(t *testing.T) {
	writer := tuiTestStore(t)
	putTUITransaction(t, writer, Transaction{ID: "existing", Time: time.Now()})
	reader, err := openStore(writer.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.db.Close()
	if _, err = reader.db.Exec("DELETE FROM requests"); err == nil {
		t.Fatal("analysis connection can modify collected data")
	}
	for _, command := range []string{"requests", "events", "show"} {
		args := []string{command}
		if command == "show" {
			args = append(args, "existing")
		}
		args = append(args, "--session", writer.dir)
		if err = run(args); err != nil {
			t.Fatalf("analysis command %s failed: %v", command, err)
		}
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if s, err := openStore(missing); err == nil {
		s.db.Close()
		t.Fatal("missing session was created")
	}
	if _, err = os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("analyst created a session directory")
	}
}
