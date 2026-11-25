package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

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
	// A click on the overview only describes the row; clicking it again opens it.
	runLoad(m, clickZone(t, m, fmt.Sprintf("ov:%d:0", blockRules)))
	if m.tab != tabOverview || m.block != blockRules || !strings.Contains(m.flash, "再点一次") {
		t.Fatalf("single click left the overview or showed no summary: %q", m.flash)
	}
	runLoad(m, clickZone(t, m, fmt.Sprintf("ov:%d:0", blockRules)))
	if m.tab != tabAlerts || m.filter.Rule == "" || m.drill == nil {
		t.Fatalf("second click did not drill %+v", m.filter)
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

func TestTUIOverviewBriefs(t *testing.T) {
	m := tuiSummaryModel(t)
	runLoad(m, m.load())
	for block, want := range map[int]string{blockRules: "规则 ", blockClients: "来源 ", blockLevels: "危告警", blockStatus: "响应 ", blockRecent: "再点一次打开详情"} {
		if brief := m.overviewBrief(block, 0); !strings.Contains(brief, want) {
			t.Errorf("block %d brief %q", block, brief)
		}
	}
	// Another row, or a key in between, needs a fresh first click.
	runLoad(m, clickZone(t, m, fmt.Sprintf("ov:%d:0", blockRecent)))
	runLoad(m, clickZone(t, m, fmt.Sprintf("ov:%d:1", blockRecent)))
	m.Update(tuiKey("up"))
	runLoad(m, clickZone(t, m, fmt.Sprintf("ov:%d:0", blockRecent)))
	if m.details || m.tab != tabOverview {
		t.Fatal("a first click on a row opened it")
	}
	// However long the pause, the second click on the same row opens it.
	m.lastClickAt = m.lastClickAt.Add(-time.Minute)
	runLoad(m, clickZone(t, m, fmt.Sprintf("ov:%d:0", blockRecent)))
	if !m.details || m.tab != tabAlerts {
		t.Fatal("second click did not open the recent alert")
	}
	runLoad(m, m.returnFromDrill())
	runLoad(m, m.load())
	// The overview timeline selects on click and drag, and opens on another click inside the selection.
	n := m.blockLen(blockTimeline)
	last := zoneOf(t, m, fmt.Sprintf("tl:%d", n-1))
	m.Update(tea.MouseClickMsg{X: last.x0, Y: last.y, Button: tea.MouseLeft})
	m.Update(tea.MouseMotionMsg{X: zoneOf(t, m, "tl:0").x0, Y: last.y, Button: tea.MouseLeft})
	m.Update(tea.MouseReleaseMsg{X: 0, Y: last.y, Button: tea.MouseLeft})
	if m.tab != tabOverview || m.timelineAnchor == 0 {
		t.Fatal("overview drag should only select")
	}
	inside := zoneOf(t, m, "tl:0")
	_, cmd := m.Update(tea.MouseClickMsg{X: inside.x0, Y: inside.y, Button: tea.MouseLeft})
	runLoad(m, cmd)
	_, cmd = m.Update(tea.MouseReleaseMsg{X: inside.x0, Y: inside.y, Button: tea.MouseLeft})
	runLoad(m, cmd)
	if m.tab != tabRequests || m.filter.Since == "" || m.filter.Until == "" {
		t.Fatalf("click inside the span did not open it %+v", m.filter)
	}
}

func TestTUIListScrollbar(t *testing.T) {
	m := tuiSummaryModel(t)
	m.tab, m.alertView = tabRequests, viewList
	for i := 0; i < 100; i++ {
		m.snapshot.Rows = append(m.snapshot.Rows, tuiRow{ID: fmt.Sprint(i), URL: fmt.Sprintf("/r%d", i)})
	}
	m.snapshot.Count = 100
	m.resize()
	_, visible := m.listLayout(m.listBox())
	first, lastCell := zoneOf(t, m, "sb:0"), zoneOf(t, m, fmt.Sprintf("sb:%d", visible-1))
	if first.x0 != m.width-1 || lastCell.y != first.y+visible-1 {
		t.Fatalf("scrollbar at %+v .. %+v", first, lastCell)
	}
	if start, thumb := tuiThumb(100, visible, 0); start != 0 || thumb != visible*visible/100 {
		t.Fatalf("thumb %d+%d", start, thumb)
	}
	if start, thumb := tuiThumb(100, visible, 100-visible); start+thumb != visible {
		t.Fatal("thumb does not reach the end at the bottom")
	}
	// A click on the track pages there; dragging the thumb to the end shows the last row.
	m.Update(tea.MouseClickMsg{X: lastCell.x0, Y: lastCell.y, Button: tea.MouseLeft})
	m.Update(tea.MouseReleaseMsg{X: lastCell.x0, Y: lastCell.y, Button: tea.MouseLeft})
	if m.listTop == 0 || m.selected < m.listTop || m.selected >= m.listTop+visible {
		t.Fatalf("track click top %d selected %d", m.listTop, m.selected)
	}
	m.Update(tea.MouseClickMsg{X: first.x0, Y: first.y, Button: tea.MouseLeft})
	m.Update(tea.MouseReleaseMsg{X: first.x0, Y: first.y, Button: tea.MouseLeft})
	start, _ := tuiThumb(100, visible, m.listTop)
	m.Update(tea.MouseClickMsg{X: first.x0, Y: first.y + start, Button: tea.MouseLeft})
	m.Update(tea.MouseMotionMsg{X: first.x0, Y: first.y + visible + 5, Button: tea.MouseLeft})
	m.Update(tea.MouseReleaseMsg{X: first.x0, Y: first.y + visible + 5, Button: tea.MouseLeft})
	if m.listTop != 100-visible || !strings.Contains(termansi.Strip(m.listView(m.listBox())), "/r99") {
		t.Fatalf("drag to the end left top at %d", m.listTop)
	}
	m.Update(tea.MouseClickMsg{X: first.x0, Y: first.y + visible - 1, Button: tea.MouseLeft})
	m.Update(tea.MouseMotionMsg{X: first.x0, Y: first.y - 3, Button: tea.MouseLeft})
	m.Update(tea.MouseReleaseMsg{X: first.x0, Y: first.y - 3, Button: tea.MouseLeft})
	if m.listTop != 0 {
		t.Fatalf("drag to the top left top at %d", m.listTop)
	}
	// Rows still fit the width beside the bar.
	for _, line := range strings.Split(m.listView(m.listBox()), "\n") {
		if termansi.StringWidth(line) > m.width {
			t.Fatalf("row overflows: %q", termansi.Strip(line))
		}
	}
}

func tuiPagedModel(t *testing.T) *tuiModel {
	t.Helper()
	s := tuiTestStore(t)
	now := time.Now().UTC()
	for i := 0; i < 250; i++ {
		putTUITransaction(t, s, Transaction{ID: fmt.Sprintf("r%03d", i), Time: now.Add(time.Duration(i-250) * time.Second), Client: "192.0.2.1:5000", Method: "GET", URL: fmt.Sprintf("/p%d", i)})
	}
	m := &tuiModel{ctx: context.Background(), store: s, refresh: time.Second, width: 160, height: 40, tab: tabRequests, alertView: viewList}
	m.resize()
	runLoad(m, m.load())
	return m
}

// The pager pages the list beside an open detail too, where n is the
// detail's search key.
func TestTUIPagerBesideDetail(t *testing.T) {
	m := tuiPagedModel(t)
	runLoad(m, clickZone(t, m, "row:3"))
	if !m.split() {
		t.Fatal("detail should open beside the list")
	}
	if !strings.Contains(m.listView(m.listBox()), "\x1b[7m") {
		t.Fatal("the open record is not marked in the list")
	}
	detail, first := m.detailID, m.snapshot.Rows[0].ID
	runLoad(m, clickZone(t, m, "page:next"))
	if m.page != 1 || m.snapshot.Rows[0].ID == first || !m.details || m.detailID != detail {
		t.Fatalf("page %d details %v", m.page, m.details)
	}
	// The open record is not on this page, so no row is marked as selected.
	if strings.Contains(m.listView(m.listBox()), "\x1b[7m") {
		t.Fatal("a row on another page is drawn as the open record")
	}
	runLoad(m, clickZone(t, m, "page:next"))
	runLoad(m, clickZone(t, m, "page:prev"))
	if m.page != 1 {
		t.Fatalf("prev went to page %d", m.page)
	}
	runLoad(m, clickZone(t, m, "page:newest"))
	if m.page != 0 {
		t.Fatal("newest did not return to the first page")
	}
	// Without a detail the pager and keys still page.
	runLoad(m, m.hideDetail())
	runLoad(m, clickZone(t, m, "page:next"))
	_, cmd := m.Update(tuiKey("n"))
	runLoad(m, cmd)
	if m.page != 2 {
		t.Fatalf("list paging reached page %d", m.page)
	}
}

func TestTUIRowClickToggles(t *testing.T) {
	m := tuiPagedModel(t)
	runLoad(m, clickZone(t, m, "row:2"))
	if !m.details || m.detailID != m.snapshot.Rows[2].ID {
		t.Fatal("first click should open the detail")
	}
	runLoad(m, clickZone(t, m, "row:4"))
	if !m.details || m.detailID != m.snapshot.Rows[4].ID {
		t.Fatal("another row should switch the detail")
	}
	runLoad(m, clickZone(t, m, "row:4"))
	if !m.details {
		t.Fatal("a double click should keep the detail open")
	}
	m.lastClickAt = time.Time{}
	runLoad(m, clickZone(t, m, "row:4"))
	if m.details || m.selected != 4 {
		t.Fatalf("second click should hide the detail (details %v selected %d)", m.details, m.selected)
	}
}

func TestTUIDividerDrag(t *testing.T) {
	m := tuiPagedModel(t)
	runLoad(m, clickZone(t, m, "row:0"))
	d := zoneOf(t, m, "divider")
	if d.x0 != m.listWidth() {
		t.Fatalf("divider at %d, list %d", d.x0, m.listWidth())
	}
	m.Update(tea.MouseClickMsg{X: d.x0 + 1, Y: d.y, Button: tea.MouseLeft})
	m.Update(tea.MouseMotionMsg{X: 61, Y: d.y, Button: tea.MouseLeft})
	if m.listWidth() != 60 || m.viewport.Width() != 160-60-3 {
		t.Fatalf("list %d detail %d", m.listWidth(), m.viewport.Width())
	}
	// Both sides keep a usable width.
	m.Update(tea.MouseMotionMsg{X: 2, Y: d.y, Button: tea.MouseLeft})
	if m.listWidth() != tuiMinList {
		t.Fatalf("list shrank to %d", m.listWidth())
	}
	m.Update(tea.MouseMotionMsg{X: 159, Y: d.y, Button: tea.MouseLeft})
	m.Update(tea.MouseReleaseMsg{X: 159, Y: d.y, Button: tea.MouseLeft})
	if m.viewport.Width() != tuiMinDetail || m.splitDrag {
		t.Fatalf("detail shrank to %d", m.viewport.Width())
	}
	content := m.View().Content
	for _, line := range strings.Split(content, "\n") {
		if termansi.StringWidth(line) > 160 {
			t.Fatal("dragged split overflows")
		}
	}
	// The proportion survives a resize; < and > go back to the fixed steps.
	m.Update(tea.WindowSizeMsg{Width: 200, Height: 40})
	if m.listWidth() <= 100 {
		t.Fatalf("ratio lost on resize: %d", m.listWidth())
	}
	d = zoneOf(t, m, "divider")
	m.Update(tea.MouseClickMsg{X: d.x0 + 1, Y: d.y, Button: tea.MouseLeft})
	m.Update(tea.MouseReleaseMsg{X: d.x0 + 1, Y: d.y, Button: tea.MouseLeft})
	m.Update(tea.MouseClickMsg{X: d.x0 + 1, Y: d.y, Button: tea.MouseLeft})
	m.Update(tea.MouseReleaseMsg{X: d.x0 + 1, Y: d.y, Button: tea.MouseLeft})
	if m.listRatio != 0 || m.listWidth() != 100 {
		t.Fatalf("double click did not reset: %d", m.listWidth())
	}
}

// On the overview timeline the first click on a column only selects it,
// even when the keyboard cursor already sits there.
func TestTUIOverviewTimelineClicks(t *testing.T) {
	m := tuiSummaryModel(t)
	runLoad(m, m.load())
	col := zoneOf(t, m, "tl:0")
	click := func() {
		_, cmd := m.Update(tea.MouseClickMsg{X: col.x0, Y: col.y, Button: tea.MouseLeft})
		runLoad(m, cmd)
		_, cmd = m.Update(tea.MouseReleaseMsg{X: col.x0, Y: col.y, Button: tea.MouseLeft})
		runLoad(m, cmd)
	}
	click()
	if m.tab != tabOverview || !strings.Contains(m.flash, "再点一次") {
		t.Fatalf("first click opened the timeline: tab %d", m.tab)
	}
	click()
	if m.tab != tabRequests || m.filter.Since == "" {
		t.Fatal("second click did not open the column")
	}
}

func TestTUIColumnDrag(t *testing.T) {
	m := tuiPagedModel(t)
	width, _ := m.listBox()
	before, _ := m.listColumns(width)
	method := before[2]
	if method.id != tuiColMethod {
		t.Fatalf("third column is %d", method.id)
	}
	b := zoneOf(t, m, fmt.Sprintf("col:%d", tuiColMethod))
	m.Update(tea.MouseClickMsg{X: b.x0, Y: b.y, Button: tea.MouseLeft})
	m.Update(tea.MouseMotionMsg{X: b.x0 + 5, Y: b.y, Button: tea.MouseLeft})
	m.Update(tea.MouseReleaseMsg{X: b.x0 + 5, Y: b.y, Button: tea.MouseLeft})
	if m.colDrag != nil || m.colWidths[tuiColMethod] != method.width+5 {
		t.Fatalf("method width %d, want %d", m.colWidths[tuiColMethod], method.width+5)
	}
	// The boundary moved with the column, and later columns follow it.
	if moved := zoneOf(t, m, fmt.Sprintf("col:%d", tuiColMethod)); moved.x0 != b.x0+5 {
		t.Fatalf("boundary at %d, want %d", moved.x0, b.x0+5)
	}
	// A column cannot crowd out the URL or vanish.
	m.lastClickAt = time.Time{}
	m.Update(tea.MouseClickMsg{X: b.x0 + 5, Y: b.y, Button: tea.MouseLeft})
	m.Update(tea.MouseMotionMsg{X: 10000, Y: b.y, Button: tea.MouseLeft})
	m.Update(tea.MouseReleaseMsg{X: 10000, Y: b.y, Button: tea.MouseLeft})
	cols, _ := m.listColumns(width)
	used := 0
	for _, c := range cols {
		used += c.width
	}
	if width-used != tuiColURLMin {
		t.Fatalf("URL left %d columns", width-used)
	}
	for _, line := range strings.Split(m.View().Content, "\n") {
		if termansi.StringWidth(line) > m.width {
			t.Fatal("widened column overflows")
		}
	}
	m.lastClickAt = time.Time{}
	b = zoneOf(t, m, fmt.Sprintf("col:%d", tuiColMethod))
	m.Update(tea.MouseClickMsg{X: b.x0, Y: b.y, Button: tea.MouseLeft})
	m.Update(tea.MouseMotionMsg{X: -100, Y: b.y, Button: tea.MouseLeft})
	m.Update(tea.MouseReleaseMsg{X: -100, Y: b.y, Button: tea.MouseLeft})
	if m.colWidths[tuiColMethod] != tuiColMin {
		t.Fatalf("method shrank to %d", m.colWidths[tuiColMethod])
	}
	// A double click on the boundary restores the automatic width.
	b = zoneOf(t, m, fmt.Sprintf("col:%d", tuiColMethod))
	m.lastClickAt = time.Time{}
	for range 2 {
		m.Update(tea.MouseClickMsg{X: b.x0, Y: b.y, Button: tea.MouseLeft})
		m.Update(tea.MouseReleaseMsg{X: b.x0, Y: b.y, Button: tea.MouseLeft})
	}
	if m.colWidths[tuiColMethod] != 0 {
		t.Fatalf("double click kept width %d", m.colWidths[tuiColMethod])
	}
}
