package main

import (
	lipgloss "charm.land/lipgloss/v2"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Sunmedalia/traffic/internal/index"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	termansi "github.com/charmbracelet/x/ansi"

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
func tuiTestStore(t testing.TB) *Store {
	t.Helper()
	dir := t.TempDir()
	db, err := index.OpenDB(dir, true)
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
	case "left":
		return tea.KeyPressMsg{Code: tea.KeyLeft}
	case "shift+right":
		return tea.KeyPressMsg{Code: tea.KeyRight, Mod: tea.ModShift}
	case "shift+tab":
		return tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}
	case "backspace":
		return tea.KeyPressMsg{Code: tea.KeyBackspace}
	case "shift+left":
		return tea.KeyPressMsg{Code: tea.KeyLeft, Mod: tea.ModShift}
	case "end":
		return tea.KeyPressMsg{Code: tea.KeyEnd}
	}
	panic(s)
}
func TestTUIRefreshAndNavigation(t *testing.T) {
	m := &tuiModel{ctx: context.Background(), store: tuiTestStore(t), refresh: time.Second, width: 100, height: 30, viewport: viewport.New(), alertView: viewList}
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
	if m.form == nil || m.form.index != formKeyword || !m.form.fields[formKeyword].input.Focused() {
		t.Fatal("form did not open on the keyword")
	}
	m.Update(tuiKey("tab"))
	m.Update(tuiKey("tab"))
	if m.form.index != formSeverity {
		t.Fatal("tab did not reach the severity choice")
	}
	m.Update(tuiKey("right"))
	m.Update(tuiKey("right"))
	for m.form.index != formSince {
		m.Update(tuiKey("tab"))
	}
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
	m := &tuiModel{ctx: context.Background(), store: tuiTestStore(t), refresh: time.Second, width: 100, height: 30, viewport: viewport.New(), tab: tabAlerts, alertView: viewList}
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
	if !strings.Contains(m.healthContent(), "java-probe-required") {
		t.Fatal("diagnostics missing from the health page")
	}
	// The overview carries the web tiles, including the drop counters.
	m.overview = &tuiOverview{}
	if !strings.Contains(m.overviewView(100, 20), "TLS 已知丢弃") {
		t.Fatal("overview tiles missing")
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
		for tab := 0; tab < detailTabCount; tab++ {
			m.detailTab = tab
			if tab == detailDecoder {
				m.currentDecoder()
			}
			m.metaOpen = tab%2 == 0
			m.msgLayout = tab % layoutCount
			m.updateContent()
			content := m.View().Content
			if lipgloss.Width(content) > size.Width || lipgloss.Height(content) > size.Height {
				t.Fatalf("overflow %dx%d got %dx%d", size.Width, size.Height, lipgloss.Width(content), lipgloss.Height(content))
			}
		}
		// Every page, list and popup also fits the terminal.
		for _, page := range []func(m *tuiModel){
			func(m *tuiModel) { m.details, m.tab = false, tabOverview },
			func(m *tuiModel) {
				m.overview = tuiParityOverview()
				for block := 0; block < blockCount; block++ {
					m.block = block
					content := m.View().Content
					if lipgloss.Width(content) > m.width || lipgloss.Height(content) > m.height {
						panic(fmt.Sprintf("overview block %d overflow", block))
					}
				}
			},
			func(m *tuiModel) {
				m.details, m.tab = false, tabRequests
				m.timeline, m.timelineKey = &tuiParityOverview().Timeline, m.timelineScope()
			},
			func(m *tuiModel) { m.analysis = &tuiAnalysis{open: true, files: []string{"custom.yaml"}} },
			func(m *tuiModel) { m.analysis = nil },
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
	// The split pane is narrower than a side-by-side pair, so the messages stack.
	if m.pairLayout() != layoutStack || !strings.Contains(m.viewport.GetContent(), "response") {
		t.Fatal("response not shown with the request")
	}
	m.msgLayout = layoutSingle
	m.updateContent()
	m.Update(tuiKey("tab"))
	if m.detailTab != detailResponse || !strings.Contains(m.viewport.GetContent(), "response") {
		t.Fatal("response tab not shown")
	}
	m.Update(tuiKey("esc"))
	if m.details || m.detailID != "" {
		t.Fatal("detail did not close")
	}
}
func TestTUISummaryAggregates(t *testing.T) {
	s := tuiTestStore(t)
	now := time.Now().UTC()
	sqli := Alert{Rule: "SQLI-001", Severity: "high", Match: "union select"}
	file := Alert{Rule: "FILE-001", Severity: "medium", Match: "/.env"}
	putTUITransaction(t, s, Transaction{ID: "1", Time: now.Add(-3 * time.Minute), Client: "203.0.113.45:5000", URL: "/a", Alerts: []Alert{sqli, file}})
	putTUITransaction(t, s, Transaction{ID: "2", Time: now.Add(-2 * time.Minute), Client: "203.0.113.45:5001", URL: "/b", Alerts: []Alert{{Rule: "SQLI-001", Severity: "high", Match: "sleep("}}})
	putTUITransaction(t, s, Transaction{ID: "3", Time: now.Add(-time.Minute), Client: "[2001:db8::1]:443", URL: "/.env", Alerts: []Alert{file}})
	putTUITransaction(t, s, Transaction{ID: "4", Time: now, Client: "192.0.2.9", URL: "/plain"})
	sum, err := loadTUISummary(context.Background(), s, tuiFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if sum.AlertRequests != 3 || sum.Levels[3] != 2 || sum.Levels[2] != 1 {
		t.Fatalf("levels %+v", sum.Levels)
	}
	if len(sum.Rules) != 2 || sum.Rules[0].Rule != "SQLI-001" || sum.Rules[0].Hits != 2 || sum.Rules[0].Sources != 1 || sum.Rules[0].Match != "sleep(" {
		t.Fatalf("rules %+v", sum.Rules)
	}
	if sum.Rules[1].Rule != "FILE-001" || sum.Rules[1].Hits != 2 || sum.Rules[1].Sources != 2 {
		t.Fatalf("file rule %+v", sum.Rules[1])
	}
	if len(sum.Sources) != 2 || sum.Sources[0].Client != "203.0.113.45" || sum.Sources[0].Hits != 2 || strings.Join(sum.Sources[0].Rules, ",") != "FILE-001,SQLI-001" || sum.Sources[1].Client != "2001:db8::1" {
		t.Fatalf("sources %+v", sum.Sources)
	}
	if len(sum.Recent) != 2 || sum.Recent[0].ID != "2" || sum.Recent[0].Rule != "SQLI-001" {
		t.Fatalf("recent %+v", sum.Recent)
	}
	// A rule condition limits which alerts of a request are aggregated.
	sum, err = loadTUISummary(context.Background(), s, tuiFilter{Rule: "FILE-001"})
	if err != nil || len(sum.Rules) != 1 || sum.Levels[2] != 2 || sum.Levels[3] != 0 || len(sum.Recent) != 0 {
		t.Fatalf("rule-filtered summary %+v %v", sum, err)
	}
	sum, err = loadTUISummary(context.Background(), s, tuiFilter{Severity: "high", Client: "203.0.113.45"})
	if err != nil || len(sum.Rules) != 1 || sum.Rules[0].Rule != "SQLI-001" || len(sum.Sources) != 1 {
		t.Fatalf("severity-filtered summary %+v %v", sum, err)
	}
}
func tuiSummaryModel(t *testing.T) *tuiModel {
	t.Helper()
	s := tuiTestStore(t)
	now := time.Now().UTC()
	putTUITransaction(t, s, Transaction{ID: "1", Time: now.Add(-time.Minute), Client: "203.0.113.45:5000", Method: "GET", URL: "/a", Alerts: []Alert{{Rule: "SQLI-001", Severity: "high"}}})
	putTUITransaction(t, s, Transaction{ID: "2", Time: now, Client: "198.51.100.7:5001", Method: "GET", URL: "/.env", Alerts: []Alert{{Rule: "FILE-001", Severity: "medium"}}})
	m := &tuiModel{ctx: context.Background(), store: s, refresh: time.Second, width: 120, height: 30, viewport: viewport.New()}
	m.resize()
	return m
}

// runLoad performs the pending query synchronously, as the event loop would.
func runLoad(m *tuiModel, cmd tea.Cmd) {
	for cmd != nil {
		msg := cmd()
		if _, ok := msg.(tuiLoaded); !ok {
			return
		}
		_, cmd = m.Update(msg)
	}
}

func TestTUIOverviewDrillAndReturn(t *testing.T) {
	m := tuiSummaryModel(t)
	runLoad(m, m.load())
	o := m.overview
	if o == nil || o.Summary.Total != 2 || o.Summary.Alerted != 2 || len(o.Recent) != 2 || o.Timeline.Total != 2 {
		t.Fatalf("overview data %+v", o)
	}
	view := m.overviewView(120, 40)
	for _, want := range []string{"SQLI-001", "累计请求", "命中规则", "来源地址", "告警级别", "响应状态", "最近告警", "采集状态"} {
		if !strings.Contains(view, want) {
			t.Fatalf("overview misses %q:\n%s", want, view)
		}
	}
	m.filter = tuiFilter{Keyword: "kept"}
	m.Update(tuiKey("tab"))
	m.Update(tuiKey("j"))
	if m.block != blockRules || m.blockSelected[blockRules] != 1 {
		t.Fatal("block navigation failed")
	}
	// Rules are ordered by request count, then name, like the web list.
	_, cmd := m.Update(tuiKey("enter"))
	if m.tab != tabAlerts || m.alertView != viewList || m.filter != (tuiFilter{Rule: "SQLI-001"}) || m.drill == nil {
		t.Fatalf("rule drill: tab=%d view=%d %+v", m.tab, m.alertView, m.filter)
	}
	runLoad(m, cmd)
	if len(m.snapshot.Rows) != 1 || m.snapshot.Rows[0].ID != "1" {
		t.Fatalf("drilled rows %+v", m.snapshot.Rows)
	}
	_, cmd = m.Update(tuiKey("esc"))
	runLoad(m, cmd)
	if m.tab != tabOverview || m.filter != (tuiFilter{Keyword: "kept"}) || m.blockSelected[blockRules] != 1 || m.drill != nil {
		t.Fatalf("return: tab=%d %+v", m.tab, m.filter)
	}
	// A source opens the request list, as on the web page.
	m.block = blockClients
	_, cmd = m.Update(tuiKey("enter"))
	if m.tab != tabRequests || m.filter.Client == "" {
		t.Fatalf("client drill: tab=%d %+v", m.tab, m.filter)
	}
	runLoad(m, cmd)
	_, cmd = m.Update(tuiKey("esc"))
	runLoad(m, cmd)
	// The timeline selects a time range of requests.
	m.block = blockTimeline
	runLoad(m, m.refreshNow())
	m.Update(tuiKey("shift+right"))
	_, cmd = m.Update(tuiKey("enter"))
	if m.tab != tabRequests || m.filter.Since == "" || m.filter.Until == "" || !m.filter.UntilExclusive {
		t.Fatalf("timeline drill %+v", m.filter)
	}
	runLoad(m, cmd)
	if m.snapshot.Count == 0 {
		t.Fatal("timeline range matched nothing")
	}
	_, cmd = m.Update(tuiKey("esc"))
	runLoad(m, cmd)
	// A recent alert opens its detail directly.
	m.block = blockRecent
	_, cmd = m.Update(tuiKey("enter"))
	runLoad(m, cmd)
	if !m.details || m.detailID != "2" || m.snapshot.Detail == nil || m.activeDetailTab() != detailRequest {
		t.Fatalf("recent alert detail not opened: details=%v id=%q detail=%v tab=%d", m.details, m.detailID, m.snapshot.Detail != nil, m.activeDetailTab())
	}
	m.Update(tuiKey("esc"))
	m.Update(tuiKey("esc"))
	if m.tab != tabOverview {
		t.Fatal("second esc did not return to the overview")
	}
}

func TestTUIAlertViewsAndDrill(t *testing.T) {
	m := tuiSummaryModel(t)
	runLoad(m, m.switchTab(tabAlerts))
	if !m.aggView() || m.alertView != viewRules || m.currentSummary() == nil || len(m.currentSummary().Rules) != 2 {
		t.Fatal("alerts tab does not open on the rule view")
	}
	_, cmd := m.Update(tuiKey("v"))
	runLoad(m, cmd)
	if m.alertView != viewSources || !strings.Contains(m.aggTable(120, 20), "198.51.100.7") {
		t.Fatal("source view missing")
	}
	runLoad(m, m.applyFilter(tuiFilter{Severity: "medium"}))
	m.Update(tuiKey("j"))
	_, cmd = m.Update(tuiKey("enter"))
	if m.filter.Severity != "medium" || m.filter.Client != "203.0.113.45" || m.alertView != viewList {
		t.Fatalf("drill lost the existing filter: %+v", m.filter)
	}
	runLoad(m, cmd)
	m.Update(tuiKey("esc"))
	if m.alertView != viewSources || m.filter != (tuiFilter{Severity: "medium"}) || m.aggSelected[viewSources] != 1 {
		t.Fatalf("esc did not restore the source view: %d %+v", m.alertView, m.filter)
	}
	m.Update(tuiKey("v"))
	m.Update(tuiKey("v"))
	if m.alertView != viewRules {
		t.Fatal("v does not cycle")
	}
	// Unchanged scope inside the interval reuses the summary.
	m.busy, m.summaryAt = false, time.Now()
	msg := m.load()().(tuiLoaded)
	if msg.Summary != nil {
		t.Fatal("summary recomputed inside the interval")
	}
	m.busy, m.summaryAt = false, time.Now().Add(-tuiSummaryInterval)
	if msg = m.load()().(tuiLoaded); msg.Summary == nil {
		t.Fatal("summary not refreshed after the interval")
	}
	for _, size := range []tea.WindowSizeMsg{{Width: 40, Height: 12}, {Width: 80, Height: 24}, {Width: 140, Height: 40}} {
		m.Update(size)
		for _, setup := range []func(){
			func() { m.tab, m.alertView = tabAlerts, viewRules },
			func() { m.tab, m.alertView = tabAlerts, viewSources },
			func() { m.tab, m.alertView = tabAlerts, viewList },
			func() { m.tab, m.summaryKey = tabOverview, "overview" },
		} {
			setup()
			content := m.View().Content
			if lipgloss.Width(content) > size.Width || lipgloss.Height(content) > size.Height {
				t.Fatalf("overflow %dx%d got %dx%d", size.Width, size.Height, lipgloss.Width(content), lipgloss.Height(content))
			}
		}
	}
}
func TestTUIHighlight(t *testing.T) {
	text := "GET /?q=UNION Select 1\nunion\nselect 中文38"
	alert := tuiPattern([]string{"union select", "union\nselect", ""})
	out := tuiHighlight(text, alert, tuiPattern([]string{"38"}))
	if termansi.Strip(out) != text {
		t.Fatalf("highlight changed the text: %q", termansi.Strip(out))
	}
	if !strings.Contains(out, tuiMatchStyle.Render("UNION Select")) || !strings.Contains(out, tuiMatchStyle.Render("union")) || !strings.Contains(out, tuiMatchStyle.Render("select")) {
		t.Fatalf("matches not marked: %q", out)
	}
	if !strings.Contains(out, tuiSearchStyle.Render("38")) {
		t.Fatal("search hit not marked")
	}
	if tuiPattern(nil) != nil || tuiHighlight("x", nil, nil) != "x" {
		t.Fatal("empty patterns")
	}
	if got := tuiOccurrences("union select", "GET /?q=union+select", ""); !strings.Contains(got, "未直接出现") {
		t.Fatalf("encoded match: %s", got)
	}
	if got := tuiOccurrences("<script>", "a <SCRIPT> b <script>", "<script>"); !strings.Contains(got, "请求中 2 处 · 响应中 1 处") {
		t.Fatalf("occurrences: %s", got)
	}
}
func TestTUIDetailSearchAndCopy(t *testing.T) {
	m := &tuiModel{ctx: context.Background(), store: tuiTestStore(t), refresh: time.Second, width: 100, height: 20, viewport: viewport.New(), tab: tabRequests, details: true, detailID: "id"}
	body := strings.Repeat("filler line\n", 40) + "needle one\n" + strings.Repeat("more\n", 40) + "NEEDLE two\n"
	m.snapshot.Detail = &Transaction{ID: "id", Request: []byte(body), Alerts: []Alert{{Rule: "R", Severity: "high", Match: "filler"}}}
	m.snapshot.Rows = []tuiRow{{ID: "id"}}
	m.resize()
	if !strings.Contains(m.viewport.GetContent(), tuiMatchStyle.Render("filler")) {
		t.Fatal("alert match not highlighted in the request")
	}
	m.Update(tuiKey("/"))
	if m.searchInput == nil || m.form != nil {
		t.Fatal("slash in detail did not open search")
	}
	for _, r := range "needle" {
		m.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	m.Update(tuiKey("enter"))
	if m.searchTerm != "needle" || len(m.searchLines) != 2 || m.viewport.YOffset() == 0 {
		t.Fatalf("search: %q lines=%v offset=%d", m.searchTerm, m.searchLines, m.viewport.YOffset())
	}
	first := m.viewport.YOffset()
	m.Update(tuiKey("n"))
	if m.searchIndex != 1 || m.viewport.YOffset() <= first {
		t.Fatal("n did not move to the next hit")
	}
	m.Update(tuiKey("N"))
	if m.searchIndex != 0 || !strings.Contains(m.noticeLine(), "第 1/2 处") {
		t.Fatalf("N did not go back: %s", m.noticeLine())
	}
	_, cmd := m.Update(tuiKey("y"))
	if cmd == nil || !strings.Contains(m.flash, "id") {
		t.Fatal("copy not issued")
	}
	m.Update(tuiKey("esc"))
	if m.searchTerm != "" || !m.details {
		t.Fatal("first esc should only clear the search")
	}
	m.Update(tuiKey("esc"))
	if m.details {
		t.Fatal("second esc should close the detail")
	}
	for _, size := range []tea.WindowSizeMsg{{Width: 40, Height: 12}, {Width: 140, Height: 40}} {
		m.details = true
		m.Update(size)
		m.openSearch()
		content := m.View().Content
		if lipgloss.Width(content) > size.Width || lipgloss.Height(content) > size.Height {
			t.Fatalf("search overflow %dx%d", size.Width, size.Height)
		}
		m.searchInput = nil
	}
}
func TestTUITimeRange(t *testing.T) {
	s := tuiTestStore(t)
	base := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		putTUITransaction(t, s, Transaction{ID: fmt.Sprint(i), Time: base.Add(time.Duration(i) * time.Hour)})
	}
	f := tuiFilter{Since: base.Add(time.Hour).Format(indexTimeFormat), Until: base.Add(3 * time.Hour).Format(indexTimeFormat)}
	result, err := loadTUISnapshot(context.Background(), s, f, false, 0, "", nil)
	if err != nil || result.Count != 3 {
		t.Fatalf("range count %d %v", result.Count, err)
	}
	form := newTUIForm(tuiFilter{}, nil, 100)
	form.now = func() time.Time { return base.Add(5 * time.Hour) }
	form.fields[formSince].input.SetValue("1h")
	form.fields[formUntil].input.SetValue("2h")
	if _, err := form.filter(); err == nil || !strings.Contains(err.Error(), "晚于") {
		t.Fatalf("reversed range accepted: %v", err)
	}
	form.fields[formUntil].input.SetValue("bad")
	if _, err := form.filter(); err == nil || !strings.HasPrefix(err.Error(), "结束时间") {
		t.Fatalf("bad until: %v", err)
	}
	form.fields[formSince].input.SetValue("3h")
	form.fields[formUntil].input.SetValue("1h")
	got, err := form.filter()
	if err != nil || got.Until == "" {
		t.Fatalf("range rejected: %v", err)
	}
	m := &tuiModel{store: s, filter: got}
	if !strings.Contains(m.filterLabel(), "– ≤") {
		t.Fatal("until chip missing")
	}
}

func TestExpiredHeartbeatChecksCaptureLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	if err := os.WriteFile(path, []byte(`{"state":"running"}`), 0600); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Add(-time.Minute)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(dir, "capture.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := session.LockFile(lock, true); err != nil {
		t.Fatal(err)
	}
	active, _ := readTUIStatus(dir)
	if active.State != "stale" {
		t.Fatalf("live lock treated as crash: %+v", active)
	}
	if err := session.UnlockFile(lock); err != nil {
		t.Fatal(err)
	}
	stopped, warning := readTUIStatus(dir)
	if stopped.State != "interrupted" || stopped.DrainState != "unverified" || warning == "" {
		t.Fatalf("unconfirmed shutdown hidden: %+v %s", stopped, warning)
	}
}

func tuiParityOverview() *tuiOverview {
	base := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	o := &tuiOverview{Summary: sessionSummary{Total: 30, Alerted: 3,
		Clients:    []webCount{{Name: "203.0.113.45", Count: 20, Alerts: 3}, {Name: "[2001:db8::1]", Count: 10}},
		Rules:      []webCount{{Name: "SQLI-001", Severity: "high", Count: 2}, {Name: "FILE-001", Severity: "medium", Count: 1}},
		Severities: []webCount{{Name: "high", Count: 2}, {Name: "medium", Count: 1}},
		Statuses:   []webCount{{Name: "2xx", Count: 25}, {Name: "4xx", Count: 3}, {Name: "pending", Count: 2}},
	}}
	o.Timeline = sessionTimeline{Total: 30, Granularity: 60}
	for i := 0; i < 30; i += 3 {
		o.Timeline.Buckets = append(o.Timeline.Buckets, webBucket{Time: base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339), Requests: 3, Alerts: i % 2})
	}
	o.Recent = []tuiRow{{ID: "r1", Time: base.Format(time.RFC3339Nano), Client: "203.0.113.45:1", Method: "GET", URL: "/a", Severity: "high"}}
	return o
}

func TestTUITimelineColumns(t *testing.T) {
	m := tuiModel{}
	o := tuiParityOverview()
	columns := m.timelineColumns(&o.Timeline, 100)
	// 28 minutes of one-minute buckets fit one column each.
	if len(columns) != 28 || columns[0].requests != 3 || columns[1].requests != 0 || columns[27].to.Sub(columns[0].from) != 28*time.Minute {
		t.Fatalf("columns %d %+v", len(columns), columns[:2])
	}
	columns = m.timelineColumns(&o.Timeline, 7)
	total := 0
	for _, c := range columns {
		total += c.requests
	}
	if len(columns) != 7 || total != 30 {
		t.Fatalf("merged columns %d total %d", len(columns), total)
	}
	tuiUseUTC.Store(true)
	defer tuiUseUTC.Store(false)
	chart := m.renderTimeline(&o.Timeline, 67, 2, false, 2, 4)
	plain := make([]string, len(chart))
	for i, line := range chart {
		plain[i] = termansi.Strip(line)
		if lipgloss.Width(line) > 67 {
			t.Fatalf("chart line %d overflows: %q", i, plain[i])
		}
	}
	// Two bar rows with the peak on the y axis, an axis with ticks and the selection, and round labels.
	if len(chart) != 4 || !strings.HasPrefix(plain[0], "    3 ┤") || !strings.Contains(plain[2], "┬") || !strings.Contains(plain[2], "━") {
		t.Fatalf("chart %q", plain)
	}
	if !strings.Contains(plain[3], "10:05") || !strings.Contains(plain[3], "10:10") || strings.Contains(plain[3], "10:07") {
		t.Fatalf("ticks %q", plain[3])
	}
	if ticks := timelineTicks(columns[0].from, columns[6].to, []int{0, 10, 20, 30, 40, 50, 60, 70}, columns); len(ticks) == 0 {
		t.Fatal("no ticks for a merged timeline")
	}
	if tuiCompact(123456) != "123k" || tuiCompact(12345) != "12.3k" || tuiCompact(999) != "999" {
		t.Fatal("compact counts")
	}
}

func TestTUIListTimelineSelection(t *testing.T) {
	m := tuiSummaryModel(t)
	runLoad(m, m.switchTab(tabRequests))
	if m.listTimeline() == nil || !strings.Contains(m.listView(120, 25), "t 选择时间范围") {
		t.Fatal("list timeline missing")
	}
	m.filter.Keyword = ""
	m.Update(tuiKey("t"))
	if !m.timelineFocus || !strings.Contains(termansi.Strip(m.listView(120, 25)), "选中") {
		t.Fatal("t did not focus the timeline")
	}
	m.Update(tuiKey("left"))
	_, cmd := m.Update(tuiKey("enter"))
	if m.timelineFocus || m.filter.Since == "" || m.filter.Until == "" || !m.filter.UntilExclusive || m.tab != tabRequests {
		t.Fatalf("range not applied %+v", m.filter)
	}
	runLoad(m, cmd)
	m.Update(tuiKey("t"))
	m.Update(tuiKey("esc"))
	if m.timelineFocus || m.filter.Since == "" {
		t.Fatal("esc should leave the timeline and keep the filter")
	}
}

func TestTUIDetailWidth(t *testing.T) {
	m := tuiDetailModel(t)
	m.width, m.height = 160, 40
	m.resize()
	if !m.split() || m.viewport.Width() != 160-80-3 {
		t.Fatalf("half split %d", m.viewport.Width())
	}
	m.Update(tuiKey(">"))
	if m.viewport.Width() != 160-53-3 || m.pairLayout() != layoutSide {
		t.Fatalf("two thirds %d", m.viewport.Width())
	}
	m.Update(tuiKey(">"))
	if m.split() || m.viewport.Width() != 160 {
		t.Fatal("detail not full screen")
	}
	content := m.View().Content
	if lipgloss.Width(content) > 160 || lipgloss.Height(content) > 40 {
		t.Fatal("full detail overflows")
	}
	m.Update(tuiKey("<"))
	m.Update(tuiKey("<"))
	m.Update(tuiKey("<"))
	if m.listShare != 0 || !m.split() {
		t.Fatal("< did not restore the list")
	}
	split := termansi.Strip(m.View().Content)
	if strings.Count(split, "│") < 20 {
		t.Fatal("split divider not drawn on every row")
	}
}

func TestTUIDecoders(t *testing.T) {
	var gz strings.Builder
	w := gzip.NewWriter(&gz)
	w.Write([]byte("hello gzip"))
	w.Close()
	cases := []struct {
		name, in, want string
		run            tuiDecodeFunc
	}{
		{"url", "a%20b+c%E4%B8%AD%zz", "a b c中%zz", tuiPercent(true)},
		{"url raw", "a+b%2B", "a+b+", tuiPercent(false)},
		{"base64", "aGVsbG8gd29ybGQ", "hello world", tuiBase64},
		{"base64 url", "PDw_Pz4-", "<<??>>", tuiBase64},
		{"hex", "0x48 0x69", "Hi", tuiHex},
		{"html", "&lt;a&#x3e;&#33;&amp;&unknown;", "<a>!&&unknown;", tuiHTML},
		{"unicode", `\u4e2d\u{1F600}%u0041\x42\n`, "中😀AB\n", tuiUnicode},
		{"gzip", gz.String(), "hello gzip", tuiInflate},
	}
	for _, tt := range cases {
		got, err := tt.run([]byte(tt.in))
		if err != nil || string(got) != tt.want {
			t.Errorf("%s: %q %v", tt.name, got, err)
		}
	}
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"
	if got, err := tuiJWT([]byte(jwt)); err != nil || !strings.Contains(string(got), `"sub": "123"`) || !strings.Contains(string(got), "sig") {
		t.Errorf("jwt %q %v", got, err)
	}
	for _, bad := range []struct {
		in  string
		run tuiDecodeFunc
	}{{"!!", tuiBase64}, {"abc", tuiHex}, {"a.b.c.d", tuiJWT}, {"plain", tuiInflate}} {
		if _, err := bad.run([]byte(bad.in)); err == nil {
			t.Errorf("accepted %q", bad.in)
		}
	}
	if !tuiDecoders[0].applies([]byte("a%20b")) || tuiDecoders[0].applies([]byte("plain")) || !tuiDecoders[7].applies([]byte(gz.String())) {
		t.Error("applies marks wrong decoders")
	}
	if !tuiLooksBinary([]byte{0, 1, 2, 3, 'a'}) || tuiLooksBinary([]byte("正文 text")) {
		t.Error("binary detection")
	}
	if dump := tuiHexDump([]byte("ABC")); !strings.HasPrefix(dump, "00000000  41 42 43") || !strings.HasSuffix(dump, "ABC") {
		t.Errorf("dump %q", dump)
	}
}

func tuiDetailModel(t *testing.T) *tuiModel {
	t.Helper()
	request := "POST /login?next=%2Fadmin&id=MTIz HTTP/1.1\r\nHost: shop\r\nCookie: sid=YWJj; theme=dark\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=%27+or+1%3D1"
	response := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true,\"items\":[1,2]}"
	detail := &Transaction{ID: "b", Method: "POST", Host: "shop", URL: "/login?next=%2Fadmin&id=MTIz", Client: "192.0.2.1:5000", Service: "nginx", Status: 200,
		Request: []byte(request), Response: []byte(response), Alerts: []Alert{{Rule: "SQLI-001", Severity: "high", Match: "' or 1=1", Field: "request.body"}}}
	m := &tuiModel{ctx: context.Background(), store: tuiTestStore(t), refresh: time.Second, width: 100, height: 40, viewport: viewport.New(), tab: tabRequests, alertView: viewList}
	m.snapshot.Rows = []tuiRow{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	m.selected = 1
	m.openDetail(m.snapshot.Rows[1])
	m.busy = false
	m.snapshot.Detail = detail
	m.resize()
	return m
}

func TestTUIDetailParity(t *testing.T) {
	m := tuiDetailModel(t)
	content := termansi.Strip(m.viewport.GetContent())
	for _, want := range []string{"[SQLI-001]", "表单参数（原文）", "pass", "Cookie（原文）", "sid", "i 展开记录信息"} {
		if !strings.Contains(content, want) {
			t.Fatalf("request tab misses %q:\n%s", want, content)
		}
	}
	// Request and response share one tab, side by side, when the pane is wide enough.
	if tabs := m.detailTabs(); len(tabs) != 3 || tabs[2] != detailAlerts {
		t.Fatalf("pair tabs %v", tabs)
	}
	pair := strings.Split(termansi.Strip(m.viewport.GetContent()), "\n")
	sideBySide := false
	for i, line := range pair {
		if strings.HasPrefix(line, "请求") && strings.Contains(line, " │ 响应") {
			sideBySide = i+1 < len(pair) && strings.Contains(pair[i+1], "POST /login") && strings.Contains(pair[i+1], "HTTP/1.1 200 OK")
		}
	}
	if !sideBySide || !strings.Contains(termansi.Strip(m.viewport.GetContent()), "请求/响应") {
		t.Fatalf("request and response not side by side:\n%s", termansi.Strip(m.viewport.GetContent()))
	}
	for _, line := range strings.Split(m.viewport.GetContent(), "\n") {
		if lipgloss.Width(line) > m.viewport.Width() {
			t.Fatalf("pair line overflows: %q", termansi.Strip(line))
		}
	}
	if _, cmd := m.Update(tuiKey("Y")); cmd == nil || !strings.Contains(m.flash, "请求和响应") {
		t.Fatalf("pair copy: %q", m.flash)
	}
	m.Update(tuiKey("L"))
	content = termansi.Strip(m.viewport.GetContent())
	if m.msgLayout != layoutStack || !strings.Contains(content, "── 请求 ") || !strings.Contains(content, "── 响应 ") || strings.Index(content, "── 响应 ") < strings.Index(content, "Cookie（原文）") {
		t.Fatalf("stacked layout:\n%s", content)
	}
	// A narrow pane falls back from side by side to stacked.
	m.msgLayout = layoutSide
	m.width = 80
	m.resize()
	if m.pairLayout() != layoutStack || !strings.Contains(m.viewport.GetContent(), "宽度不足") {
		t.Fatal("narrow pane did not stack")
	}
	m.width = 100
	m.msgLayout = layoutStack
	m.Update(tuiKey("L"))
	if m.msgLayout != layoutSingle {
		t.Fatal("L did not reach the single layout")
	}
	if tabs := m.detailTabs(); len(tabs) != 4 || tabs[3] != detailAlerts {
		t.Fatalf("tabs %v", tabs)
	}
	m.Update(tuiKey("i"))
	if !strings.Contains(termansi.Strip(m.viewport.GetContent()), "S 按服务筛选") {
		t.Fatal("record information not expanded")
	}
	m.Update(tuiKey("]"))
	if m.activeDetailTab() != detailResponse || !strings.Contains(m.viewport.GetContent(), "  \"ok\": true") {
		t.Fatalf("response not pretty printed:\n%s", m.viewport.GetContent())
	}
	m.Update(tuiKey("f"))
	if !strings.Contains(m.viewport.GetContent(), `{"ok":true,"items":[1,2]}`) {
		t.Fatal("raw body toggle failed")
	}
	if _, cmd := m.Update(tuiKey("Y")); cmd == nil || !strings.Contains(m.flash, "响应") {
		t.Fatalf("copy content: %q", m.flash)
	}
	m.Update(tuiKey("["))
	m.Update(tuiKey("["))
	if m.activeDetailTab() != detailAlerts {
		t.Fatalf("[ did not wrap to the evidence tab: %d", m.activeDetailTab())
	}
	// d opens the decoder on the alert match from the evidence tab.
	m.Update(tuiKey("d"))
	if m.activeDetailTab() != detailDecoder || m.decoder.label != "命中片段 SQLI-001" {
		t.Fatalf("decoder source %q", m.decoder.label)
	}
	m.Update(tuiKey("left"))
	if m.decoder.label != "请求正文" {
		t.Fatalf("previous source %q", m.decoder.label)
	}
	// Choose the id query parameter and decode it twice through the picker.
	for m.decoder.label != "查询参数 id" {
		m.Update(tuiKey("right"))
	}
	m.Update(tuiKey("enter"))
	if !m.decoder.picking || !m.modal() {
		t.Fatal("picker not open")
	}
	for tuiDecoders[m.decoder.pick].label != "Base64" {
		m.Update(tuiKey("j"))
	}
	m.Update(tuiKey("enter"))
	if string(m.decoder.last()) != "123" || len(m.decoder.steps) != 2 {
		t.Fatalf("decode result %q", m.decoder.last())
	}
	m.Update(tuiKey("backspace"))
	if len(m.decoder.steps) != 1 {
		t.Fatal("undo failed")
	}
	m.Update(tuiKey("w"))
	m.decoder.editor.SetValue("%41")
	m.Update(tuiKey("enter"))
	if m.decoder.label != "手动输入" || m.decoder.input != "%41" || m.modal() {
		t.Fatal("manual input not applied")
	}
	// j and k change record, as on the web page.
	_, cmd := m.Update(tuiKey("j"))
	if cmd == nil || m.detailID != "c" || m.selected != 2 {
		t.Fatalf("j did not open the next record: %q", m.detailID)
	}
	m.busy = false
	m.Update(tuiKey("k"))
	if m.detailID != "b" {
		t.Fatalf("k did not open the previous record: %q", m.detailID)
	}
}

func TestTUIFormParity(t *testing.T) {
	f := tuiFilter{Keyword: "admin", Decode: 2, Status: "403", Method: "TRACE", HideStatic: true, Exclude: "a b", Param: "cmd", Since: "2026-11-16T10:00:00.123000000Z", Until: "2026-11-16T11:00:00.000000000Z", UntilExclusive: true}
	form := newTUIForm(f, []string{"nginx"}, 100)
	got, err := form.filter()
	if err != nil || got != f {
		t.Fatalf("round trip changed the filter:\n%+v\n%+v %v", got, f, err)
	}
	form.fields[formCode].input.SetValue("")
	form.fields[formStatus].choice = 5
	form.fields[formParam].input.SetValue("a=b")
	if _, err := form.filter(); err == nil {
		t.Fatal("invalid parameter accepted")
	}
	form.fields[formParam].input.SetValue("")
	if got, err = form.filter(); err != nil || got.Status != "pending" {
		t.Fatalf("status class %+v %v", got, err)
	}
	m := &tuiModel{filter: got}
	label := m.filterLabel()
	for _, want := range []string{"URL 解码 2 次", "状态 待响应", "方法 TRACE", "隐藏静态资源", "排除 a b"} {
		if !strings.Contains(label, want) {
			t.Fatalf("chips miss %q: %s", want, label)
		}
	}
	if view := form.view(8); lipgloss.Height(view) > 8 {
		t.Fatalf("form overflow %d", lipgloss.Height(view))
	}
}

func TestTUIAnalysisDialog(t *testing.T) {
	m := tuiSummaryModel(t)
	m.rulesDir = filepath.Join(t.TempDir(), "rules")
	if err := os.MkdirAll(m.rulesDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.rulesDir, "custom.yaml"), []byte(testManagedRules), 0600); err != nil {
		t.Fatal(err)
	}
	m.snapshot.Stats.State = "running"
	m.Update(tuiKey("A"))
	if m.analysis == nil || !m.analysis.open || len(m.analysis.files) != 1 || !m.modal() {
		t.Fatal("dialog did not list the rule directory")
	}
	m.Update(tuiKey("j"))
	if m.analysis.choice != 1 {
		t.Fatal("rule choice did not move")
	}
	m.Update(tuiKey("enter"))
	if m.analysis.job != nil || !strings.Contains(m.analysis.err, "采集仍在进行") {
		t.Fatalf("running capture analysed: %q", m.analysis.err)
	}
	m.snapshot.Stats.State = "stopped"
	_, cmd := m.Update(tuiKey("enter"))
	if !m.analysisRunning() || cmd == nil || !strings.Contains(m.identityLine(120), "分析中") {
		t.Fatalf("job did not start: %q", m.analysis.err)
	}
	m.Update(tuiKey("esc"))
	if m.analysis.open || !m.analysisRunning() {
		t.Fatal("closing the dialog stopped the job")
	}
	m.Update(tuiAnalysisDone{ID: m.analysis.job.id, Err: errors.New("boom")})
	if m.analysis.job.state != "failed" || !strings.Contains(m.flash, "boom") {
		t.Fatalf("failure not reported: %q", m.flash)
	}
	m.Update(tuiKey("A"))
	if m.analysis.choice != 1 || !strings.Contains(m.analysisView(30), "失败") {
		t.Fatal("dialog lost its state")
	}
	_, cmd = m.Update(tuiKey("enter"))
	m.Update(tuiKey("x"))
	if !m.analysis.cancelling {
		t.Fatal("cancel not requested")
	}
	m.Update(tuiAnalysisDone{ID: m.analysis.job.id, Err: context.Canceled})
	if m.analysis.job.state != "cancelled" || len(m.analysis.history) != 2 || !strings.Contains(m.analysisView(30), "最近任务") {
		t.Fatal("cancel not reported")
	}
	_ = cmd
	m.Update(tuiAnalysisDone{ID: m.analysis.job.id, Report: analysisReport{Alerts: 3}})
	if m.analysis.job.state != "cancelled" {
		t.Fatal("finished job changed state twice")
	}
}

func TestTUIZoneToggle(t *testing.T) {
	defer tuiUseUTC.Store(false)
	m := &tuiModel{store: tuiTestStore(t), viewport: viewport.New(), width: 100, height: 30}
	m.Update(tuiKey("z"))
	if !tuiUseUTC.Load() || !strings.Contains(m.tabsLine(100), "UTC") {
		t.Fatal("UTC not selected")
	}
	stamp := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	if got := tuiTime(stamp.Format(time.RFC3339Nano)); got != "11-16 10:00:00" {
		t.Fatalf("UTC time %q", got)
	}
	if got, err := parseTUISince("2026-11-16 10:00", stamp.Add(time.Hour)); err != nil || !got.Equal(stamp) {
		t.Fatalf("UTC parse %v %v", got, err)
	}
	m.Update(tuiKey("z"))
	if tuiUseUTC.Load() {
		t.Fatal("local time not restored")
	}
}
