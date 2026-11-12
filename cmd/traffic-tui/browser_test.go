package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

func TestDiscoverSessionsByIndex(t *testing.T) {
	legacy := tuiTestStore(t)
	modern := tuiTestStore(t)
	now := time.Now().UTC()
	if err := os.WriteFile(filepath.Join(modern.dir, "manifest.json"), []byte(`{"name":"正常访问","hostname":"web-01","started":"2026-11-12T03:48:10Z","layout_version":2}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modern.dir, "status.json"), []byte(`{"state":"stopped","transactions":5,"alerts":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	putTUITransaction(t, legacy, Transaction{ID: "legacy", Time: now})
	broken := t.TempDir()
	if err := os.WriteFile(filepath.Join(broken, "index.sqlite"), []byte("broken database"), 0600); err != nil {
		t.Fatal(err)
	}
	exports := t.TempDir()
	if err := os.WriteFile(filepath.Join(exports, "manifest.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	// Duplicate roots must not duplicate sessions. Exports alone are not sessions.
	result := discoverSessions(context.Background(), []string{filepath.Dir(legacy.dir), legacy.dir})
	if len(result.Entries) != 3 {
		t.Fatalf("found %+v", result)
	}
	found := map[string]sessionEntry{}
	for _, entry := range result.Entries {
		found[entry.Dir] = entry
	}
	if found[legacy.dir].Problem != "" || found[modern.dir].Name != "正常访问" || found[modern.dir].Host != "web-01" || found[modern.dir].Stats.Transactions != 5 || found[broken].Problem == "" {
		t.Fatalf("incorrect recognition: %+v", found)
	}
	if sessionPath(filepath.Join(modern.dir, "index.sqlite")) != modern.dir {
		t.Fatal("index path not normalized")
	}
}

func TestBrowserSwitchRejectsOldSessionResults(t *testing.T) {
	first, second := tuiTestStore(t), tuiTestStore(t)
	putTUITransaction(t, second, Transaction{ID: "second", Time: time.Now()})
	m := &sessionBrowser{ctx: context.Background(), refresh: time.Second, width: 100, height: 30}
	defer m.closeSession()
	if err := m.openSession(first.dir); err != nil {
		t.Fatal(err)
	}
	generation := m.generation
	if err := m.openSession(second.dir); err != nil {
		t.Fatal(err)
	}
	m.Update(sessionChildMsg{generation, tuiLoaded{Version: 0, Snapshot: tuiSnapshot{Count: 999}}})
	if m.child.snapshot.Count != 1 {
		t.Fatal("old session result replaced current session")
	}
	m.Update(tuiKey("/"))
	m.Update(tuiKey("s"))
	if m.child == nil || !m.child.filtering {
		t.Fatal("typing s in filter switched session")
	}
	m.Update(tuiKey("esc"))
	_, cmd := m.Update(tuiKey("s"))
	if m.child != nil || cmd == nil {
		t.Fatal("did not return to browser")
	}
	m.Update(sessionChildMsg{generation, tuiTick(time.Now())})
	if m.child != nil {
		t.Fatal("old refresh reopened session")
	}
}

func TestBrowserCommandBatchesAndLayout(t *testing.T) {
	cmd := sessionCommand(tea.Batch(func() tea.Msg { return tuiTick(time.Now()) }, func() tea.Msg { return tuiTick(time.Now()) }), 7)
	batch, ok := cmd().(tea.BatchMsg)
	if !ok || len(batch) != 2 {
		t.Fatal("batch not preserved")
	}
	message, ok := batch[0]().(sessionChildMsg)
	if !ok || message.Generation != 7 {
		t.Fatal("batch child not tagged")
	}
	m := &sessionBrowser{roots: []string{"/会话/" + strings.Repeat("长", 100)}, entries: []sessionEntry{{Name: "正常访问", Dir: "/test"}}}
	for _, size := range []tea.WindowSizeMsg{{Width: 80, Height: 24}, {Width: 140, Height: 40}, {Width: 40, Height: 12}, {Width: 20, Height: 5}} {
		m.Update(size)
		content := m.View().Content
		if lipgloss.Width(content) > size.Width || lipgloss.Height(content) > size.Height {
			t.Fatalf("browser overflow %dx%d", size.Width, size.Height)
		}
	}
}
