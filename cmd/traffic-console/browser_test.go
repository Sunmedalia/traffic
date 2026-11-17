package main

import (
	lipgloss "charm.land/lipgloss/v2"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
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
	nested := filepath.Join(legacy.dir, "packets", "nested")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "index.sqlite"), []byte("not a session"), 0600); err != nil {
		t.Fatal(err)
	}
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
	if m.child == nil || m.child.form == nil {
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
	if _, ok := sessionCommand(tea.SetClipboard("id"), 7)().(sessionChildMsg); ok {
		t.Fatal("runtime clipboard message was hidden from Bubble Tea")
	}
	m := &sessionBrowser{roots: []string{"/会话/" + strings.Repeat("长", 100)}, query: newSessionQuery()}
	m.Update(sessionsFound{Entries: []sessionEntry{{Name: "正常访问", Dir: "/test", Host: "web-01"}, {Name: "夜间", Dir: "/night", Host: "web-01", Stats: Stats{State: "running"}}, {Name: "后台", Dir: "/admin", Host: "db-02"}}})
	for _, size := range []tea.WindowSizeMsg{{Width: 80, Height: 24}, {Width: 140, Height: 40}, {Width: 40, Height: 12}, {Width: 20, Height: 5}} {
		m.Update(size)
		content := m.View().Content
		if lipgloss.Width(content) > size.Width || lipgloss.Height(content) > size.Height {
			t.Fatalf("browser overflow %dx%d", size.Width, size.Height)
		}
	}
}

func TestBrowserGroupsAndSearches(t *testing.T) {
	now := time.Now()
	m := &sessionBrowser{query: newSessionQuery(), width: 100, height: 30, lastDir: "/old"}
	m.Update(sessionsFound{Entries: []sessionEntry{
		{Name: "最新", Dir: "/new", Host: "web-01", Started: now},
		{Name: "后台", Dir: "/admin", Host: "db-02", Started: now.Add(-time.Minute)},
		{Name: "采集中", Dir: "/live", Host: "web-01", Started: now.Add(-time.Hour), Stats: Stats{State: "running"}},
		{Name: "旧", Dir: "/old", Host: "web-01", Started: now.Add(-2 * time.Hour)},
	}})
	got := []string{}
	for _, index := range m.order {
		got = append(got, m.entries[index].Dir)
	}
	if strings.Join(got, ",") != "/live,/new,/old,/admin" {
		t.Fatalf("bad grouping %v", got)
	}
	if m.selectedDir() != "/old" {
		t.Fatalf("returning did not keep the opened session: %s", m.selectedDir())
	}
	m.Update(tuiKey("/"))
	for _, r := range "后台" {
		m.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	if len(m.order) != 1 || m.selectedDir() != "/admin" {
		t.Fatalf("search failed: %v", m.order)
	}
	m.Update(tuiKey("esc"))
	if m.searching || len(m.order) != 4 {
		t.Fatal("esc did not clear search")
	}
}

func TestDiscoverSessionsInvalidatesCache(t *testing.T) {
	store := tuiTestStore(t)
	if err := os.WriteFile(filepath.Join(store.dir, "status.json"), []byte(`{"state":"stopped","transactions":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	cache := newDiscoveryCache()
	first := discoverSessions(context.Background(), []string{store.dir}, cache)
	if len(first.Entries) != 1 || first.Entries[0].Problem != "" {
		t.Fatalf("first discovery: %+v", first)
	}
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.dir, "index.sqlite"), []byte("broken database"), 0600); err != nil {
		t.Fatal(err)
	}
	second := discoverSessions(context.Background(), []string{store.dir}, cache)
	if len(second.Entries) != 1 || second.Entries[0].Problem == "" {
		t.Fatalf("cache did not invalidate: %+v", second)
	}
}
