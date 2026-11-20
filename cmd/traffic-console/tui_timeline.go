package main

// The request and alert timeline, shared by the overview and the lists. It
// draws a y axis with the peak, ticks on round times, alerting requests in
// red on top of each bar and the selected span highlighted on the bars, and
// it lets the keyboard select a time range the way dragging does on the web.

import (
	"fmt"
	"strings"
	"time"

	lipgloss "charm.land/lipgloss/v2"
	termansi "github.com/charmbracelet/x/ansi"
)

// tuiTimelineGutter is the y axis: a five-cell value, a space and the axis line.
const tuiTimelineGutter = 7

var tuiTimelineSelected = lipgloss.Color("#23414A")

type tuiTimelineColumn struct {
	from, to         time.Time
	requests, alerts int
}

// timelinePlot is the bar area width beside the y axis.
func (m tuiModel) timelinePlot() int { return max(10, m.width-tuiTimelineGutter) }

// timelineColumns spreads the buckets over at most width columns. Short
// timelines get one column per bucket; long ones merge neighbouring buckets.
func (m tuiModel) timelineColumns(data *sessionTimeline, width int) []tuiTimelineColumn {
	if data == nil || data.Total == 0 || len(data.Buckets) == 0 {
		return nil
	}
	step := time.Duration(max(1, data.Granularity)) * time.Second
	start, err := time.Parse(time.RFC3339, data.Buckets[0].Time)
	if err != nil {
		return nil
	}
	last, err := time.Parse(time.RFC3339, data.Buckets[len(data.Buckets)-1].Time)
	if err != nil {
		return nil
	}
	n := min(2000, int(last.Sub(start)/step)+1)
	cols := max(1, min(n, width))
	columns := make([]tuiTimelineColumn, cols)
	for i := range columns {
		lo, hi := i*n/cols, (i+1)*n/cols
		columns[i].from, columns[i].to = start.Add(time.Duration(lo)*step), start.Add(time.Duration(hi)*step)
	}
	for _, bucket := range data.Buckets {
		at, err := time.Parse(time.RFC3339, bucket.Time)
		if err != nil {
			continue
		}
		index := int(at.Sub(start) / step)
		if index < 0 || index >= n {
			continue
		}
		c := &columns[index*cols/n]
		c.requests += bucket.Requests
		c.alerts += bucket.Alerts
	}
	return columns
}

// timelineRange is the selected column span, or the cursor column alone.
func (m tuiModel) timelineRange(n int) (int, int) {
	cursor := max(0, min(n-1, m.blockSelected[blockTimeline]))
	if m.timelineAnchor == 0 {
		return cursor, cursor
	}
	anchor := max(0, min(n-1, m.timelineAnchor-1))
	return min(anchor, cursor), max(anchor, cursor)
}

// timelineSelection returns the selected span as index times; the end is exclusive.
func (m tuiModel) timelineSelection(data *sessionTimeline) (string, string) {
	columns := m.timelineColumns(data, m.timelinePlot())
	if len(columns) == 0 {
		return "", ""
	}
	from, to := m.timelineRange(len(columns))
	return columns[from].from.UTC().Format(indexTimeFormat), columns[to].to.UTC().Format(indexTimeFormat)
}

// moveTimeline moves the cursor; shifted arrows extend a range from where they start.
func (m *tuiModel) moveTimeline(key string, n int) {
	cursor := &m.blockSelected[blockTimeline]
	switch key {
	case "shift+left", "shift+right", "H", "L":
		if m.timelineAnchor == 0 {
			m.timelineAnchor = *cursor + 1
		}
	case "left", "right", "h", "l", "home", "end", "g", "G":
		m.timelineAnchor = 0
	}
	switch key {
	case "left", "h", "shift+left", "H":
		*cursor--
	case "right", "l", "shift+right", "L":
		*cursor++
	case "pgup":
		*cursor -= max(1, n/10)
	case "pgdown":
		*cursor += max(1, n/10)
	case "home", "g":
		*cursor = 0
	case "end", "G":
		*cursor = n - 1
	}
	*cursor = max(0, min(n-1, *cursor))
}

// tuiCompact fits a count into the five-cell y axis.
func tuiCompact(n int) string {
	switch {
	case n >= 10_000_000:
		return fmt.Sprintf("%dM", n/1_000_000)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 100_000:
		return fmt.Sprintf("%dk", n/1000)
	case n >= 10_000:
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	}
	return fmt.Sprint(n)
}

var tuiTickSteps = []time.Duration{
	time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second, 15 * time.Second, 30 * time.Second,
	time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 15 * time.Minute, 30 * time.Minute,
	time.Hour, 2 * time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour,
	2 * 24 * time.Hour, 7 * 24 * time.Hour, 14 * 24 * time.Hour, 30 * 24 * time.Hour,
}

type tuiAxisTick struct {
	x     int
	label string
}

// timelineTicks picks round times whose labels fit the plot without overlapping.
func timelineTicks(start, end time.Time, positions []int, columns []tuiTimelineColumn) []tuiAxisTick {
	span := end.Sub(start)
	if span <= 0 {
		return nil
	}
	plot := positions[len(positions)-1]
	crossesDay := tuiIn(start).YearDay() != tuiIn(end.Add(-time.Nanosecond)).YearDay() || tuiIn(start).Year() != tuiIn(end).Year()
	for _, step := range tuiTickSteps {
		layout := "15:04"
		switch {
		case step >= 24*time.Hour:
			layout = "01-02"
		case crossesDay:
			layout = "01-02 15:04"
		case step < time.Minute:
			layout = "15:04:05"
		}
		labelWidth := len(layout) + 3
		if int(span/step)+1 > max(1, plot/labelWidth) {
			continue
		}
		// Align to the step in the displayed time zone.
		local := tuiIn(start)
		first := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, tuiZone())
		if step < 24*time.Hour {
			first = first.Add(local.Sub(first).Truncate(step))
		}
		ticks := []tuiAxisTick{}
		last := -labelWidth
		for t := first; !t.After(end); t = t.Add(step) {
			if t.Before(start) {
				continue
			}
			// Place the tick at the column containing t.
			x := plot
			for i, c := range columns {
				if !t.Before(c.from) && t.Before(c.to) {
					x = positions[i]
					break
				}
			}
			if x-last < labelWidth || x+len(layout) > plot {
				continue
			}
			ticks = append(ticks, tuiAxisTick{x, tuiIn(t).Format(layout)})
			last = x
		}
		return ticks
	}
	return nil
}

// renderTimeline draws height bar rows, an axis row and a label row. selected
// marks the highlighted column span; from > to draws none.
func (m tuiModel) renderTimeline(data *sessionTimeline, width, height int, alertsOnly bool, from, to int) []string {
	plot := max(10, width-tuiTimelineGutter)
	columns := m.timelineColumns(data, plot)
	if len(columns) == 0 {
		return []string{tuiMuted.Render("这个范围内没有请求")}
	}
	// Spread the leftover cells so the bars span the full width.
	widths := make([]int, len(columns))
	positions := make([]int, len(columns)+1)
	for i := range widths {
		widths[i] = max(1, (i+1)*plot/len(columns)-i*plot/len(columns))
		positions[i+1] = positions[i] + widths[i]
	}
	peak := 1
	for _, c := range columns {
		peak = max(peak, c.requests)
	}
	units := func(n int) int {
		if n == 0 {
			return 0
		}
		return max(1, (n*height*8+peak-1)/peak)
	}
	blocks := []rune(" ▁▂▃▄▅▆▇█")
	lines := make([]string, 0, height+2)
	for row := height - 1; row >= 0; row-- {
		gutter := strings.Repeat(" ", tuiTimelineGutter-1) + "│"
		switch row {
		case height - 1:
			gutter = fmt.Sprintf("%5s ┤", tuiCompact(peak))
		case 0:
			if height > 2 {
				gutter = fmt.Sprintf("%5s ┤", "0")
			}
		}
		var b strings.Builder
		b.WriteString(tuiMuted.Render(gutter))
		base := row * 8
		for i, c := range columns {
			total, hit := units(c.requests), units(c.alerts)
			if alertsOnly {
				hit = total
			}
			fill := max(0, min(8, total-base))
			style := tuiBar
			switch {
			case fill == 0:
				style = lipgloss.NewStyle()
			case hit > base:
				style = tuiDanger
			}
			if i >= from && i <= to {
				style = style.Background(tuiTimelineSelected)
			}
			b.WriteString(style.Render(strings.Repeat(string(blocks[fill]), widths[i])))
		}
		lines = append(lines, b.String())
	}
	ticks := timelineTicks(columns[0].from, columns[len(columns)-1].to, positions, columns)
	axis := []rune(strings.Repeat("─", plot))
	for _, t := range ticks {
		if t.x < len(axis) {
			axis[t.x] = '┬'
		}
	}
	var b strings.Builder
	b.WriteString(tuiMuted.Render(strings.Repeat(" ", tuiTimelineGutter-1) + "└"))
	for i := range columns {
		segment := string(axis[positions[i]:positions[i+1]])
		if i >= from && i <= to {
			b.WriteString(tuiAccent.Render(strings.Repeat("━", widths[i])))
		} else {
			b.WriteString(tuiMuted.Render(segment))
		}
	}
	lines = append(lines, b.String())
	labels := []rune(strings.Repeat(" ", plot+tuiTimelineGutter))
	for _, t := range ticks {
		copy(labels[tuiTimelineGutter+t.x:], []rune(t.label))
	}
	return append(lines, tuiMuted.Render(strings.TrimRight(string(labels), " ")))
}

// timelineSummary describes the whole timeline, or the selected span.
func (m tuiModel) timelineSummary(data *sessionTimeline, focused bool) string {
	columns := m.timelineColumns(data, m.timelinePlot())
	if len(columns) == 0 {
		return ""
	}
	format := timelineFormat(columns)
	sum := func(cs []tuiTimelineColumn) (int, int) {
		requests, alerts := 0, 0
		for _, c := range cs {
			requests, alerts = requests+c.requests, alerts+c.alerts
		}
		return requests, alerts
	}
	if !focused {
		requests, alerts := sum(columns)
		text := fmt.Sprintf("%s – %s · 每格 %s · %s 请求", format(columns[0].from), format(columns[len(columns)-1].to), tuiDuration(int(columns[0].to.Sub(columns[0].from).Seconds())), tuiCount(uint64(requests)))
		if alerts > 0 {
			text += " · " + tuiDanger.Render(tuiCount(uint64(alerts))+" 含告警")
		}
		return text + "  " + tuiBar.Render("█") + " 请求 " + tuiDanger.Render("█") + " 含告警"
	}
	from, to := m.timelineRange(len(columns))
	requests, alerts := sum(columns[from : to+1])
	total, _ := sum(columns)
	text := tuiAccent.Render(fmt.Sprintf("选中 %s – %s", format(columns[from].from), format(columns[to].to))) + fmt.Sprintf(" · %s 请求", tuiCount(uint64(requests)))
	if alerts > 0 {
		text += " · " + tuiDanger.Render(tuiCount(uint64(alerts))+" 含告警")
	}
	if total > 0 {
		text += fmt.Sprintf(" · 占 %d%%", (requests*100+total/2)/total)
	}
	return text + tuiMuted.Render(" · ←→ 移动 · Shift+←→ 选范围 · Enter 查看 · Esc 取消")
}

func (m tuiModel) timelineBlock(width, height int) []string {
	data := &m.overview.Timeline
	focused := m.block == blockTimeline
	from, to := 1, 0
	if focused {
		from, to = m.timelineRange(len(m.timelineColumns(data, m.timelinePlot())))
	}
	return append([]string{m.blockTitle(blockTimeline, m.timelineSummary(data, focused))}, m.renderTimeline(data, width, height, false, from, to)...)
}

// listTimelineView is the strip above a list: one sparkline row, or a full
// chart while t has the timeline selecting a range.
func (m tuiModel) listTimelineView(data *sessionTimeline, width int) []string {
	alertsOnly := m.tab == tabAlerts
	if m.timelineFocus {
		from, to := m.timelineRange(len(m.timelineColumns(data, m.timelinePlot())))
		return append([]string{m.timelineSummary(data, true)}, m.renderTimeline(data, width, 3, alertsOnly, from, to)...)
	}
	chart := m.renderTimeline(data, width, 1, alertsOnly, 1, 0)
	if len(chart) < 3 {
		return chart[:1]
	}
	// One bar row, with the range and the key that opens the selector in the gutter line.
	columns := m.timelineColumns(data, m.timelinePlot())
	format := timelineFormat(columns)
	info := tuiMuted.Render(fmt.Sprintf("时间线  %s – %s · 每格 %s · t 选择时间范围", format(columns[0].from), format(columns[len(columns)-1].to), tuiDuration(int(columns[0].to.Sub(columns[0].from).Seconds()))))
	return []string{termansi.Truncate(info, width, "…"), chart[0]}
}

func tuiFormatTime(t time.Time, style string) string {
	t = tuiIn(t)
	switch style {
	case "date":
		return t.Format("2006-01-02")
	case "dayclock":
		return t.Format("01-02 15:04")
	case "clock":
		return t.Format("15:04:05")
	}
	return t.Format("2006-01-02 15:04:05")
}

// timelineFormat drops the date when the whole timeline falls on one day.
func timelineFormat(columns []tuiTimelineColumn) func(time.Time) string {
	first, last := tuiIn(columns[0].from), tuiIn(columns[len(columns)-1].to.Add(-time.Nanosecond))
	if first.YearDay() != last.YearDay() || first.Year() != last.Year() {
		return func(t time.Time) string { return tuiFormatTime(t, "dayclock") }
	}
	return func(t time.Time) string { return tuiFormatTime(t, "clock") }
}
