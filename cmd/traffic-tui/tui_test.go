package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/Sunmedalia/traffic/internal/session"
)

func putTUITransaction(t *testing.T, s *Store, transaction Transaction) {
	t.Helper()
	b, err := json.Marshal(transaction)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.db.Exec("INSERT OR REPLACE INTO requests VALUES(?,?,?,?,?)", transaction.ID, transaction.Time.UTC().Format(indexTimeFormat), transaction.Client, len(transaction.Alerts), b)
	if err != nil {
		t.Fatal(err)
	}
}
func tuiTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	db, err := session.OpenDB(dir, true)
	s := &Store{db: db, dir: dir}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.Close() })
	return s
}
func TestTUIQueriesExistingSession(t *testing.T) {
	writer := tuiTestStore(t)
	now := time.Now().UTC()
	alerts := []Alert{{Rule: "RULE-A", Severity: "high"}, {Rule: "RULE-B", Severity: "low"}}
	putTUITransaction(t, writer, Transaction{ID: "a", Time: now, Client: "[2001:db8::1]:123", Host: "demo", URL: "/100%_ok", Request: []byte("GET / HTTP/1.1\r\n\r\n"), Alerts: alerts})
	putTUITransaction(t, writer, Transaction{ID: "b", Time: now.Add(-time.Hour), Client: "192.0.2.1:80", Host: "other", URL: "/plain"})
	reader, err := openStore(writer.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.db.Close()
	cases := []struct {
		name   string
		filter tuiFilter
		alerts bool
		want   int
	}{
		{"all", tuiFilter{}, false, 2},
		{"alerts", tuiFilter{}, true, 1},
		{"IPv6 host", tuiFilter{Client: "2001:db8::1"}, false, 1},
		{"IPv6 endpoint", tuiFilter{Client: "[2001:db8::1]:123"}, false, 1},
		{"IPv4 host", tuiFilter{Client: "192.0.2.1"}, false, 1},
		{"IPv4 prefix must not match", tuiFilter{Client: "192.0.2"}, false, 0},
		{"same alert", tuiFilter{Rule: "RULE-A", Severity: "high"}, false, 1},
		{"at least low", tuiFilter{Rule: "RULE-A", Severity: "low"}, false, 1},
		{"at least medium", tuiFilter{Severity: "medium"}, false, 1},
		{"different alerts", tuiFilter{Rule: "RULE-B", Severity: "medium"}, false, 0},
		{"literal wildcard", tuiFilter{Keyword: "%_"}, false, 1},
		{"host", tuiFilter{Keyword: "demo"}, false, 1},
		{"since", tuiFilter{Since: now.Add(-time.Minute).Format(indexTimeFormat)}, false, 1},
		{"empty", tuiFilter{Rule: "missing"}, false, 0},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			result, err := loadTUISnapshot(context.Background(), reader, tt.filter, tt.alerts, 0, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			if result.Count != tt.want || len(result.Rows) != tt.want {
				t.Fatalf("count=%d rows=%d want=%d", result.Count, len(result.Rows), tt.want)
			}
		})
	}
	result, err := loadTUISnapshot(context.Background(), reader, tuiFilter{}, false, 0, "a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Rows[0].Severity != "high" || result.Rows[0].Rule != "RULE-A" || result.Detail == nil || len(result.Detail.Request) == 0 {
		t.Fatalf("bad detail/summary: %+v", result)
	}
	transaction := *result.Detail
	transaction.Response = []byte("HTTP/1.1 200 OK\r\n\r\nupdated")
	transaction.Status = 200
	putTUITransaction(t, writer, transaction)
	result, err = loadTUISnapshot(context.Background(), reader, tuiFilter{}, false, 0, "a", nil)
	if err != nil || result.Detail == nil || result.Detail.Status != 200 {
		t.Fatalf("response update missing: %+v %v", result, err)
	}
	if _, err = writer.db.Exec("DELETE FROM requests WHERE id='a'"); err != nil {
		t.Fatal(err)
	}
	result, err = loadTUISnapshot(context.Background(), reader, tuiFilter{}, false, 0, "a", nil)
	if err != nil || !result.DetailMissing {
		t.Fatalf("deleted detail: %+v %v", result, err)
	}
}
func TestTUIPaginationAndStableHistory(t *testing.T) {
	s := tuiTestStore(t)
	now := time.Now().UTC()
	for i := 0; i < 205; i++ {
		putTUITransaction(t, s, Transaction{ID: fmt.Sprintf("%03d", i), Time: now})
	}
	first, err := loadTUISnapshot(context.Background(), s, tuiFilter{}, false, 0, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadTUISnapshot(context.Background(), s, tuiFilter{}, false, 1, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Rows) != 100 || len(second.Rows) != 100 || first.Rows[99].ID == second.Rows[0].ID || second.Rows[0].ID != "104" {
		t.Fatalf("bad pages: %+v", second)
	}
	putTUITransaction(t, s, Transaction{ID: "new", Time: now.Add(time.Second)})
	stable, err := loadTUISnapshot(context.Background(), s, tuiFilter{}, false, 1, "", &second.Rows[0])
	if err != nil || stable.Rows[0].ID != "104" {
		t.Fatalf("history shifted: %+v %v", stable, err)
	}
	last, err := loadTUISnapshot(context.Background(), s, tuiFilter{}, false, 999, "", nil)
	if err != nil || last.Page != 2 || len(last.Rows) != 6 {
		t.Fatalf("bad last page: %+v %v", last, err)
	}
	if _, err = s.db.Exec("DELETE FROM requests WHERE id != 'new'"); err != nil {
		t.Fatal(err)
	}
	clamped, err := loadTUISnapshot(context.Background(), s, tuiFilter{}, false, 1, "", &second.Rows[0])
	if err != nil || clamped.Page != 0 || len(clamped.Rows) != 1 {
		t.Fatalf("retention clamp: %+v %v", clamped, err)
	}
	// An anchored tail may disappear while enough newer records remain for the page.
	for i := 0; i < 105; i++ {
		putTUITransaction(t, s, Transaction{ID: fmt.Sprintf("fresh-%03d", i), Time: now.Add(time.Hour)})
	}
	refreshed, err := loadTUISnapshot(context.Background(), s, tuiFilter{}, false, 1, "", &second.Rows[0])
	if err != nil || len(refreshed.Rows) == 0 {
		t.Fatalf("empty historical tail not recovered: %+v %v", refreshed, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = loadTUISnapshot(ctx, s, tuiFilter{}, false, 0, "", nil); err == nil {
		t.Fatal("ignored cancellation")
	}
}
func TestTUIStatusAndUntrustedText(t *testing.T) {
	dir := t.TempDir()
	if _, warning := readTUIStatus(dir); warning == "" {
		t.Fatal("missing status not indicated")
	}
	path := filepath.Join(dir, "status.json")
	if err := os.WriteFile(path, []byte(`{"state":"running"}`), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	status, warning := readTUIStatus(dir)
	if status.State != "stale" || warning == "" {
		t.Fatal("missing stale heartbeat")
	}
	if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, warning = readTUIStatus(dir); warning == "" {
		t.Fatal("invalid JSON not indicated")
	}
	input := "中文\x1b[2J\x1b]52;c;payload\a正文\n\ttext\x00\x1b["
	clean := cleanTUIText(input)
	if strings.ContainsAny(clean, "\x1b\a\x00\t") || !strings.Contains(clean, "中文") || !strings.Contains(clean, "\n") {
		t.Fatalf("unsafe/invalid text %q", clean)
	}
}
func tuiKey(s string) tea.KeyPressMsg {
	if len([]rune(s)) == 1 {
		return tea.KeyPressMsg{Code: []rune(s)[0], Text: s}
	}
	switch s {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "tab":
		return tea.KeyPressMsg{Code: tea.KeyTab}
	case "right":
		return tea.KeyPressMsg{Code: tea.KeyRight}
	}
	panic(s)
}
func TestTUIRefreshAndNavigation(t *testing.T) {
	m := &tuiModel{ctx: context.Background(), store: tuiTestStore(t), refresh: time.Second, width: 100, height: 30, viewport: viewport.New()}
	m.snapshot.Rows = []tuiRow{{ID: "old"}, {ID: "selected"}}
	m.resize()
	m.Update(tuiKey("2"))
	if !m.busy || m.version != 1 || m.tab != tabRequests || !m.stale {
		t.Fatal("navigation did not schedule a versioned load")
	}
	m.Update(tuiKey("3"))
	if !m.pending || m.version != 2 {
		t.Fatal("in-flight query did not queue navigation")
	}
	_, cmd := m.Update(tuiLoaded{Version: 1, Snapshot: tuiSnapshot{Rows: []tuiRow{{ID: "stale"}}}})
	if cmd == nil || m.snapshot.Rows[0].ID == "stale" {
		t.Fatal("stale query applied")
	}
	m.Update(tuiLoaded{Version: 2, Snapshot: tuiSnapshot{Rows: []tuiRow{{ID: "old"}, {ID: "selected"}}}})
	// Following keeps the cursor on the newest record.
	m.Update(tuiLoaded{Version: 2, Snapshot: tuiSnapshot{Rows: []tuiRow{{ID: "new"}, {ID: "old"}, {ID: "selected"}}}})
	if m.selected != 0 || !m.following() {
		t.Fatal("following cursor moved")
	}
	m.Update(tuiKey("j"))
	if m.following() {
		t.Fatal("moving the cursor did not freeze the list")
	}
	m.busy = false
	m.load()
	m.Update(tuiLoaded{Version: 2, Snapshot: tuiSnapshot{Rows: []tuiRow{{ID: "newer"}, {ID: "new"}, {ID: "old"}}, Newer: 1}})
	if m.snapshot.Rows[m.selected].ID != "old" {
		t.Fatal("frozen selection not retained by ID")
	}
	if !strings.Contains(m.listView(100, 10), "新增 1 条") {
		t.Fatal("new records not announced")
	}
	m.Update(tuiLoaded{Version: 2, Err: errors.New("busy")})
	if m.errorText == "" || len(m.snapshot.Rows) != 3 {
		t.Fatal("last result lost on failure")
	}
	m.Update(tuiLoaded{Version: 2, Snapshot: tuiSnapshot{Rows: []tuiRow{{ID: "old"}}}})
	if m.errorText != "" {
		t.Fatal("failure did not recover")
	}
	m.Update(tuiKey("g"))
	if !m.following() {
		t.Fatal("g did not resume following")
	}
	m.busy = false
	m.Update(tuiKey(" "))
	m.Update(tuiTick(time.Now()))
	if !m.paused || m.busy {
		t.Fatal("paused refresh scheduled a query")
	}
	m.Update(tuiKey("r"))
	if !m.busy {
		t.Fatal("manual refresh while paused failed")
	}
	m.Update(tuiKey("/"))
	if m.form == nil || m.form.index != formSeverity {
		t.Fatal("form did not open")
	}
	m.Update(tuiKey("right"))
	m.Update(tuiKey("right"))
	m.Update(tuiKey("tab"))
	if !m.form.fields[formSince].input.Focused() {
		t.Fatal("tab did not focus the time field")
	}
	m.form.fields[formSince].input.SetValue("someday")
	m.Update(tuiKey("enter"))
	if m.form == nil || m.form.err == "" {
		t.Fatal("invalid time accepted")
	}
	m.form.fields[formSince].input.SetValue("2026-11-11T10:00:00+08:00")
	m.Update(tuiKey("enter"))
	if m.form != nil || m.filter.Since != "2026-11-11T02:00:00.000000000Z" || m.filter.Severity != "medium" {
		t.Fatalf("form not applied: %+v", m.filter)
	}
	if !strings.Contains(m.filterLabel(), "级别 ≥ 中") {
		t.Fatalf("missing chip: %s", m.filterLabel())
	}
	m.Update(tuiKey("x"))
	if m.filter != (tuiFilter{}) {
		t.Fatal("x did not clear filters")
	}
}
func TestTUIRowFiltersAndTabs(t *testing.T) {
	m := &tuiModel{ctx: context.Background(), store: tuiTestStore(t), refresh: time.Second, width: 100, height: 30, viewport: viewport.New(), tab: tabAlerts}
	m.snapshot.Rows = []tuiRow{{ID: "a", Client: "[2001:db8::1]:443", Rule: "SQLI-001", Host: "shop"}, {ID: "b", Client: "192.0.2.1:80"}}
	m.resize()
	m.Update(tuiKey("c"))
	if m.filter.Client != "2001:db8::1" || m.tab != tabAlerts {
		t.Fatalf("client filter: %+v", m.filter)
	}
	m.Update(tuiLoaded{Version: m.version, Snapshot: tuiSnapshot{Rows: m.snapshot.Rows}})
	m.Update(tuiKey("c"))
	if m.filter.Client != "" {
		t.Fatal("second c did not remove the condition")
	}
	m.Update(tuiLoaded{Version: m.version, Snapshot: tuiSnapshot{Rows: []tuiRow{{ID: "a", Rule: "SQLI-001", Host: "shop"}}}})
	m.Update(tuiKey("m"))
	m.Update(tuiLoaded{Version: m.version, Snapshot: tuiSnapshot{Rows: []tuiRow{{ID: "a", Rule: "SQLI-001", Host: "shop"}}}})
	m.Update(tuiKey("H"))
	if m.filter.Rule != "SQLI-001" || m.filter.Keyword != "shop" {
		t.Fatalf("rule/host filter: %+v", m.filter)
	}
	// Each list tab keeps its own cursor.
	m.Update(tuiLoaded{Version: m.version, Snapshot: tuiSnapshot{Rows: []tuiRow{{ID: "a"}, {ID: "b"}, {ID: "c"}}}})
	m.Update(tuiKey("j"))
	m.Update(tuiKey("j"))
	m.Update(tuiKey("2"))
	m.Update(tuiKey("3"))
	if m.selected != 2 {
		t.Fatalf("cursor not restored: %d", m.selected)
	}
	m.Update(tuiKey("4"))
	if m.tab != tabHealth || m.listTab() {
		t.Fatal("health tab missing")
	}
	m.Update(tuiKey("esc"))
	if m.tab != tabHealth {
		t.Fatal("esc at top level changed page")
	}
}
func TestTUIHealthLevels(t *testing.T) {
	m := &tuiModel{store: tuiTestStore(t), viewport: viewport.New()}
	if level, _ := m.tuiHealth(); level != 0 {
		t.Fatal("clean capture flagged")
	}
	m.snapshot.Stats = Stats{State: "running", TLSDropped: 3, Targets: []session.Target{{Service: "tomcat", State: "java-probe-required"}}}
	level, reasons := m.tuiHealth()
	if level != 1 || len(reasons) != 2 || !strings.Contains(m.noticeLine(), "TLS 已知丢弃 3") {
		t.Fatalf("warnings: %d %v", level, reasons)
	}
	m.snapshot.Stats.State = "stale"
	if level, _ = m.tuiHealth(); level != 2 {
		t.Fatal("stale heartbeat not critical")
	}
	if !strings.Contains(m.healthContent(), "java-probe-required") || strings.Contains(m.overview(), "网卡丢包") {
		t.Fatal("diagnostics not moved to the health page")
	}
}
func TestTUIParseSince(t *testing.T) {
	now := time.Date(2026, 11, 16, 15, 46, 12, 0, time.Local)
	cases := map[string]time.Time{
		"30m":                       now.Add(-30 * time.Minute),
		"2h":                        now.Add(-2 * time.Hour),
		"1d":                        now.AddDate(0, 0, -1),
		"today":                     time.Date(2026, 11, 16, 0, 0, 0, 0, time.Local),
		"14:30":                     time.Date(2026, 11, 16, 14, 30, 0, 0, time.Local),
		"16:00":                     time.Date(2026, 11, 15, 16, 0, 0, 0, time.Local),
		"11-16 14:30":               time.Date(2026, 11, 16, 14, 30, 0, 0, time.Local),
		"12-31 23:00":               time.Date(2025, 12, 31, 23, 0, 0, 0, time.Local),
		"2026-11-11 10:00":          time.Date(2026, 11, 11, 10, 0, 0, 0, time.Local),
		"2026-11-11T10:00:00+08:00": time.Date(2026, 11, 11, 2, 0, 0, 0, time.UTC),
	}
	for input, want := range cases {
		got, err := parseTUISince(input, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("%s: got %v %v want %v", input, got, err, want)
		}
	}
	for _, input := range []string{"", "later", "-5m", "0d", "3dd"} {
		if _, err := parseTUISince(input, now); err == nil {
			t.Errorf("%q accepted", input)
		}
	}
}
func TestTUIExportPopup(t *testing.T) {
	s := tuiTestStore(t)
	putTUITransaction(t, s, Transaction{ID: "ev/1", Time: time.Now(), Client: "192.0.2.1:80", Request: []byte("GET / HTTP/1.1\r\n\r\n")})
	m := &tuiModel{ctx: context.Background(), store: s, refresh: time.Second, width: 100, height: 30, viewport: viewport.New(), tab: tabRequests}
	m.snapshot.Rows = []tuiRow{{ID: "ev/1", Method: "GET", URL: "/"}}
	m.Update(tuiKey("e"))
	if m.export == nil || m.export.input.Value() != "./evidence-ev_1.zip" {
		t.Fatal("export popup missing")
	}
	out := filepath.Join(t.TempDir(), "evidence.zip")
	m.export.input.SetValue(out)
	_, cmd := m.Update(tuiKey("enter"))
	if cmd == nil || !m.export.running {
		t.Fatal("export not started")
	}
	m.Update(cmd())
	if m.export == nil || !strings.Contains(m.export.err, "导出失败") {
		t.Fatal("missing capture lock not reported")
	}
	if err := os.WriteFile(filepath.Join(s.dir, "capture.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	_, cmd = m.Update(tuiKey("enter"))
	m.Update(cmd())
	if m.export != nil || !strings.Contains(m.flash, out) {
		t.Fatalf("export result: %+v %q", m.export, m.flash)
	}
	m.Update(tuiKey("e"))
	m.export.input.SetValue(out)
	_, cmd = m.Update(tuiKey("enter"))
	m.Update(cmd())
	if m.export == nil || !strings.Contains(m.export.err, "已存在") {
		t.Fatal("existing file overwritten")
	}
}
func TestTUILayoutAndDetailTabs(t *testing.T) {
	m := &tuiModel{store: tuiTestStore(t), viewport: viewport.New(), details: true, detailID: "id", tab: tabRequests}
	m.snapshot.Detail = &Transaction{ID: "id", URL: "/中文" + strings.Repeat("长", 100), Request: []byte(strings.Repeat("正文\n", 200)), Response: []byte("HTTP/1.1 200 OK\r\n\r\nresponse"), Alerts: []Alert{{Rule: "R", Severity: "high", Match: "matched"}}}
	m.snapshot.Rows = []tuiRow{{ID: "id", URL: "/中文" + strings.Repeat("长", 100)}}
	for _, size := range []tea.WindowSizeMsg{{Width: 40, Height: 12}, {Width: 80, Height: 24}, {Width: 140, Height: 40}, {Width: 20, Height: 5}} {
		m.Update(size)
		for tab := 0; tab < 4; tab++ {
			m.detailTab = tab
			m.updateContent()
			content := m.View().Content
			if lipgloss.Width(content) > size.Width || lipgloss.Height(content) > size.Height {
				t.Fatalf("overflow %dx%d got %dx%d", size.Width, size.Height, lipgloss.Width(content), lipgloss.Height(content))
			}
		}
		// Every page, list and popup also fits the terminal.
		for _, page := range []func(m *tuiModel){
			func(m *tuiModel) { m.details, m.tab = false, tabOverview },
			func(m *tuiModel) { m.details, m.tab = false, tabRequests },
			func(m *tuiModel) { m.details, m.tab = false, tabHealth },
			func(m *tuiModel) {
				m.details, m.tab = false, tabAlerts
				m.form = newTUIForm(tuiFilter{Severity: "high"}, m.services(), m.width)
			},
			func(m *tuiModel) { m.form = nil; m.help = true },
		} {
			page(m)
			m.resize()
			content := m.View().Content
			if lipgloss.Width(content) > size.Width || lipgloss.Height(content) > size.Height {
				t.Fatalf("page overflow %dx%d got %dx%d", size.Width, size.Height, lipgloss.Width(content), lipgloss.Height(content))
			}
		}
		m.help, m.details, m.tab = false, true, tabRequests
	}
	m.width = 140
	m.height = 40
	m.detailTab = 0
	m.resize()
	m.Update(tuiKey("tab"))
	if m.detailTab != 1 || !strings.Contains(m.viewport.GetContent(), "response") {
		t.Fatal("response tab not shown")
	}
	m.Update(tuiKey("esc"))
	if m.details || m.detailID != "" {
		t.Fatal("detail did not close")
	}
}
