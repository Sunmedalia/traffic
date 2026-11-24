package main

// List columns. Each column before the URL has an automatic width that
// follows the page; dragging the boundary at its right end in the header
// fixes the width, and a double click on the boundary returns it to automatic.

import (
	"fmt"
	"time"

	"charm.land/lipgloss/v2"
)

const (
	tuiColTime = iota
	tuiColLevel
	tuiColMethod
	tuiColStatus
	tuiColClient
	tuiColHost
	tuiColCount
)

var tuiColTitles = [tuiColCount]string{"时间", "级", "方法", "状态", "来源", "Host"}

// The narrowest a dragged column gets, and the room it always leaves the URL.
const (
	tuiColMin    = 3
	tuiColURLMin = 10
)

type tuiListColumn struct {
	id, width int
}

// tuiColumnDrag follows a press on a column boundary in the list header.
type tuiColumnDrag struct {
	col, x, width int // the column, where the press landed, and its width then
	moved         bool
}

// listColumns lays out the columns before the URL for a list width. Narrow
// lists keep time, level, method and status. today reports whether every row
// is from today, so times can drop the date.
func (m tuiModel) listColumns(width int) ([]tuiListColumn, bool) {
	now := time.Now()
	today := true
	for _, r := range m.snapshot.Rows {
		if !tuiIsToday(r.Time, now) {
			today = false
			break
		}
	}
	auto := [tuiColCount]int{tuiColTime: 15, tuiColLevel: 3, tuiColMethod: 7, tuiColStatus: 7}
	if today {
		auto[tuiColTime] = 10
	}
	ids := []int{tuiColTime, tuiColLevel, tuiColMethod, tuiColStatus}
	if width >= 80 {
		ids = append(ids, tuiColClient)
		auto[tuiColClient] = 17
		for _, r := range m.snapshot.Rows {
			auto[tuiColClient] = max(auto[tuiColClient], min(41, lipgloss.Width(tuiLine(m.clientText(r, width)))+2))
		}
	}
	if width >= 100 {
		ids = append(ids, tuiColHost)
		auto[tuiColHost] = 12
		for _, r := range m.snapshot.Rows {
			auto[tuiColHost] = max(auto[tuiColHost], min(28, lipgloss.Width(tuiLine(r.Host))+2))
		}
	}
	cols := make([]tuiListColumn, len(ids))
	for i, id := range ids {
		cols[i] = tuiListColumn{id, auto[id]}
		if w := m.colWidths[id]; w > 0 {
			cols[i].width = w
		}
	}
	return cols, today
}

// columnHeader draws a column title with its draggable boundary in the last cell.
func (m tuiModel) columnHeader(c tuiListColumn) string {
	edge := tuiMuted.Render("╎")
	if d := m.colDrag; d != nil && d.col == c.id {
		edge = tuiAccent.Render("┃")
	}
	return tuiMuted.Render(tuiCell(tuiColTitles[c.id], c.width-1)) + tuiHit(fmt.Sprintf("col:%d", c.id), edge)
}

// startColumnDrag holds a column boundary pressed at x; a double click
// returns the column to its automatic width.
func (m *tuiModel) startColumnDrag(col, x int, double bool) {
	if col < 0 || col >= tuiColCount {
		return
	}
	if double {
		m.colDrag = nil
		m.colWidths[col] = 0
		m.flash = tuiColTitles[col] + "列已恢复自动宽度"
		return
	}
	width, _ := m.listBox()
	cols, _ := m.listColumns(width)
	for _, c := range cols {
		if c.id == col {
			m.colDrag = &tuiColumnDrag{col: col, x: x, width: c.width}
			return
		}
	}
}

// dragColumn follows the pointer with the held boundary, leaving the URL room.
func (m *tuiModel) dragColumn(x int) {
	d := m.colDrag
	if d == nil {
		return
	}
	width, _ := m.listBox()
	cols, _ := m.listColumns(width)
	others := 0
	for _, c := range cols {
		if c.id != d.col {
			others += c.width
		}
	}
	limit := max(tuiColMin, width-others-tuiColURLMin)
	next := max(tuiColMin, min(limit, d.width+x-d.x))
	if next != d.width || d.moved {
		d.moved = true
		m.colWidths[d.col] = next
	}
}

// endColumnDrag releases the boundary and tells the column's new width.
func (m *tuiModel) endColumnDrag() {
	d := m.colDrag
	m.colDrag = nil
	if d == nil || !d.moved {
		return
	}
	m.flash = fmt.Sprintf("%s列 %d 列 · 双击列边界恢复自动宽度", tuiColTitles[d.col], m.colWidths[d.col])
}
