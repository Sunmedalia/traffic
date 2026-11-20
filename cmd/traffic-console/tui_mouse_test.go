package main

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	termansi "github.com/charmbracelet/x/ansi"
)

// zoneOf finds where a zone was drawn in the current frame.
func zoneOf(t *testing.T, m *tuiModel, id string) tuiHitZone {
	t.Helper()
	for _, z := range m.zones() {
		if z.id == id {
			return z
		}
	}
	ids := []string{}
	for _, z := range m.zones() {
		ids = append(ids, z.id)
	}
	t.Fatalf("zone %q not drawn; have %v", id, ids)
	return tuiHitZone{}
}

func clickZone(t *testing.T, m *tuiModel, id string) tea.Cmd {
	t.Helper()
	z := zoneOf(t, m, id)
	_, cmd := m.Update(tea.MouseClickMsg{X: z.x0, Y: z.y, Button: tea.MouseLeft})
	return cmd
}

func TestTUIHitScan(t *testing.T) {
	line := "ab" + tuiHit("one", "中文") + tuiMuted.Render(tuiHit("two", "cd")) + "\n" + tuiHit("outer", "x"+tuiHit("inner", "y")+"z")
	clean, zones := tuiHitScan(line)
	if strings.Contains(clean, "\x1b_") || termansi.Strip(clean) != "ab中文cd\nxyz" {
		t.Fatalf("markers left %q", clean)
	}
	want := map[string]tuiHitZone{"one": {"one", 0, 2, 6}, "two": {"two", 0, 6, 8}, "inner": {"inner", 1, 1, 2}, "outer": {"outer", 1, 0, 3}}
	for _, z := range zones {
		if want[z.id] != z {
			t.Fatalf("zone %+v, want %+v", z, want[z.id])
		}
	}
	if tuiHitFind(zones, 1, 1) != "inner" || tuiHitFind(zones, 0, 1) != "outer" || tuiHitFind(zones, 1, 0) != "" {
		t.Fatal("innermost zone not chosen")
	}
	// A zone cut by truncation still ends at its line.
	_, zones = tuiHitScan(tuiHitOpen + "open" + tuiHitST + "abc\nd")
	if len(zones) != 1 || zones[0] != (tuiHitZone{"open", 0, 0, 3}) {
		t.Fatalf("unterminated zone %+v", zones)
	}
}

func TestTUIHints(t *testing.T) {
	_, zones := tuiHitScan(tuiHints("j/k 上下一条 · [ ] 切标签 · Esc 返回 · ↑↓ 滚动 · 1-4 切换页面"))
	got := []string{}
	for _, z := range zones {
		got = append(got, fmt.Sprintf("%s@%d-%d", z.id, z.x0, z.x1))
	}
	want := "key:j@0-1 key:k@2-3 key:[@15-16 key:]@17-18 key:esc@28-36 key:up@39-40 key:down@40-41"
	if strings.Join(got, " ") != want {
		t.Fatalf("hint zones %s", strings.Join(got, " "))
	}
	for _, name := range []string{"enter", "esc", "space", "ctrl+r", "shift+tab", "L", "?", "pgdown"} {
		if got := tuiKeyMsg(name).String(); got != name {
			t.Fatalf("key %q reads back as %q", name, got)
		}
	}
}

func TestTUIMouseList(t *testing.T) {
	m := tuiSummaryModel(t)
	runLoad(m, m.switchTab(tabRequests))
	view := m.View()
	if view.MouseMode != tea.MouseModeCellMotion || strings.Contains(view.Content, "\x1b_") {
		t.Fatal("view must ask for the mouse and hide zone markers")
	}
	// Tabs switch pages.
	runLoad(m, clickZone(t, m, "tab:2"))
	if m.tab != tabAlerts {
		t.Fatalf("tab click went to %d", m.tab)
	}
	runLoad(m, clickZone(t, m, "tab:1"))
	// A row click opens that record.
	runLoad(m, clickZone(t, m, "row:1"))
	if !m.details || m.detailID != m.snapshot.Rows[1].ID || m.selected != 1 {
		t.Fatalf("row click opened %q", m.detailID)
	}
	// Detail tabs and the hints under them are clickable.
	runLoad(m, clickZone(t, m, fmt.Sprintf("dtab:%d", detailDecoder)))
	if m.activeDetailTab() != detailDecoder {
		t.Fatal("detail tab click ignored")
	}
	runLoad(m, clickZone(t, m, "key:esc"))
	if m.details {
		t.Fatal("Esc hint did not close the detail")
	}
	// Right click goes back too.
	runLoad(m, clickZone(t, m, "row:0"))
	_, cmd := m.Update(tea.MouseClickMsg{X: 1, Y: 1, Button: tea.MouseRight})
	runLoad(m, cmd)
	if m.details {
		t.Fatal("right click did not go back")
	}
	// A chip click removes its condition only.
	runLoad(m, m.applyFilter(tuiFilter{Keyword: "env", Rule: "FILE-001"}))
	runLoad(m, clickZone(t, m, "chip:keyword"))
	if m.filter != (tuiFilter{Rule: "FILE-001"}) {
		t.Fatalf("chip removed the wrong condition %+v", m.filter)
	}
	runLoad(m, clickZone(t, m, "key:x"))
	if m.filter != (tuiFilter{}) {
		t.Fatal("x 清空 hint did not clear")
	}
	// The filter label opens the form, where options and buttons are clickable.
	clickZone(t, m, "filter")
	if m.form == nil {
		t.Fatal("filter label did not open the form")
	}
	clickZone(t, m, fmt.Sprintf("fopt:%d:1", formSeverity))
	runLoad(m, clickZone(t, m, "key:enter"))
	if m.form != nil || m.filter.Severity != "high" {
		t.Fatalf("form click did not apply %+v", m.filter)
	}
	// M gives the mouse back to the terminal.
	m.Update(tuiKey("M"))
	if m.View().MouseMode != tea.MouseModeNone {
		t.Fatal("M did not release the mouse")
	}
}

func TestTUIMouseWheelList(t *testing.T) {
	m := tuiSummaryModel(t)
	m.tab, m.alertView = tabRequests, viewList
	for i := 0; i < 60; i++ {
		m.snapshot.Rows = append(m.snapshot.Rows, tuiRow{ID: fmt.Sprint(i), URL: fmt.Sprintf("/r%d", i)})
	}
	m.snapshot.Count = 60
	m.resize()
	_, visible := m.listLayout(m.listBox())
	m.Update(tea.MouseWheelMsg{X: 5, Y: 10, Button: tea.MouseWheelDown})
	if m.listTop != 3 || m.selected != 3 {
		t.Fatalf("wheel top %d selected %d", m.listTop, m.selected)
	}
	plain := termansi.Strip(m.listView(m.listBox()))
	if !strings.Contains(plain, "/r3") || strings.Contains(plain, "/r2\n") {
		t.Fatalf("list did not scroll:\n%s", plain)
	}
	// The keyboard scrolls only as far as needed to keep the cursor visible.
	for i := 0; i < visible+2; i++ {
		m.Update(tuiKey("down"))
	}
	if m.selected != visible+5 || m.listTop != m.selected-visible+1 {
		t.Fatalf("cursor %d top %d visible %d", m.selected, m.listTop, visible)
	}
	m.Update(tuiKey("up"))
	if m.listTop != m.selected-visible+2 {
		t.Fatal("moving up should not scroll while the cursor is visible")
	}
	for i := 0; i < 40; i++ {
		m.Update(tea.MouseWheelMsg{X: 5, Y: 10, Button: tea.MouseWheelUp})
	}
	if m.listTop != 0 || m.selected != visible-1 {
		t.Fatalf("wheel up top %d selected %d", m.listTop, m.selected)
	}
}

func TestTUIMouseTimelineDrag(t *testing.T) {
	m := tuiSummaryModel(t)
	runLoad(m, m.switchTab(tabRequests))
	n := len(m.timelineColumns(m.listTimeline(), m.timelinePlot()))
	if n < 2 {
		t.Fatalf("timeline has %d columns", n)
	}
	first, last := zoneOf(t, m, "tl:0"), zoneOf(t, m, fmt.Sprintf("tl:%d", n-1))
	// A click selects one column without filtering.
	m.Update(tea.MouseClickMsg{X: last.x0, Y: last.y, Button: tea.MouseLeft})
	m.Update(tea.MouseReleaseMsg{X: last.x0, Y: last.y, Button: tea.MouseLeft})
	if !m.timelineFocus || m.timelineAnchor != 0 || m.blockSelected[blockTimeline] != n-1 || m.filter.Since != "" {
		t.Fatal("click should select a column")
	}
	// Dragging across columns applies the span, like the web timeline.
	last = zoneOf(t, m, fmt.Sprintf("tl:%d", n-1))
	m.Update(tea.MouseClickMsg{X: last.x0, Y: last.y, Button: tea.MouseLeft})
	m.Update(tea.MouseMotionMsg{X: first.x0 - 3, Y: 0, Button: tea.MouseLeft})
	_, cmd := m.Update(tea.MouseReleaseMsg{X: first.x0 - 3, Y: 0, Button: tea.MouseLeft})
	runLoad(m, cmd)
	if m.timelineFocus || m.filter.Since == "" || m.filter.Until == "" || !m.filter.UntilExclusive {
		t.Fatalf("drag did not filter %+v", m.filter)
	}
}

func TestTUIMouseOverviewAndParams(t *testing.T) {
	m := tuiSummaryModel(t)
	runLoad(m, m.load())
	runLoad(m, clickZone(t, m, fmt.Sprintf("ov:%d:0", blockRules)))
	if m.tab != tabAlerts || m.filter.Rule == "" || m.drill == nil {
		t.Fatalf("rule click did not drill %+v", m.filter)
	}

	d := tuiDetailModel(t)
	d.setDetailTab(detailParams)
	clickZone(t, d, "param:1")
	if d.activeDetailTab() != detailDecoder || d.decoder.label != "查询参数 id" {
		t.Fatalf("param click opened %q", d.decoder.label)
	}
	clickZone(t, d, "key:enter")
	clickZone(t, d, "dpick:2")
	if len(d.decoder.steps) != 2 {
		t.Fatalf("picker click did not decode: %+v", d.decoder.err)
	}
	clickZone(t, d, "dstep:0")
	if len(d.decoder.steps) != 1 {
		t.Fatal("step click did not go back")
	}
	before := d.viewport.YOffset()
	d.Update(tea.MouseWheelMsg{X: 5, Y: 10, Button: tea.MouseWheelDown})
	if d.viewport.YOffset() <= before && d.viewport.TotalLineCount() > d.viewport.Height() {
		t.Fatal("wheel did not scroll the detail")
	}
}
