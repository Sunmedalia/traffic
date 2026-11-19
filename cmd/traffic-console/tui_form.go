package main

// Filter form and relative time parsing.

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

type tuiFormField struct {
	label  string
	values []string
	names  []string
	choice int
	input  textinput.Model
}
type tuiForm struct {
	fields []tuiFormField
	index  int
	err    string
	now    func() time.Time
}

const (
	formSeverity = iota
	formSince
	formUntil
	formClient
	formRule
	formService
	formKeyword
)

func newTUIForm(f tuiFilter, services []string, width int) *tuiForm {
	text := func(label, hint, value string) tuiFormField {
		input := textinput.New()
		input.SetVirtualCursor(true)
		input.SetValue(value)
		input.Placeholder = hint
		input.SetWidth(max(10, width-24))
		input.CharLimit = 512
		return tuiFormField{label: label, input: input}
	}
	local := func(stamp string) string {
		if t, err := time.Parse(indexTimeFormat, stamp); err == nil {
			return t.Local().Format("2006-01-02 15:04:05")
		}
		return ""
	}
	since, until := local(f.Since), local(f.Until)
	form := &tuiForm{now: time.Now}
	severity := tuiFormField{label: "级别", values: []string{"", "low", "medium", "high"}, names: []string{"全部", "低及以上", "中及以上", "仅高"}}
	service := tuiFormField{label: "服务", values: append([]string{""}, services...), names: append([]string{"全部"}, services...)}
	for i, v := range severity.values {
		if v == f.Severity {
			severity.choice = i
		}
	}
	for i, v := range service.values {
		if v == f.Service {
			service.choice = i
		}
	}
	form.fields = []tuiFormField{
		severity,
		text("时间从", "30m、2h、1d、today、14:30、11-16 14:30 或 RFC3339", since),
		text("时间到", "留空表示到现在，格式同上", until),
		text("客户端", "IP 或 IP:端口", f.Client),
		text("规则", "规则 ID，例如 SQLI-001", f.Rule),
		service,
		text("关键词", "Host 或 URL 包含的文字", f.Keyword),
	}
	return form
}
func (f *tuiForm) focus() tea.Cmd {
	for i := range f.fields {
		f.fields[i].input.Blur()
	}
	if f.fields[f.index].values == nil {
		return f.fields[f.index].input.Focus()
	}
	return nil
}
func (f *tuiForm) update(msg tea.Msg) tea.Cmd {
	field := &f.fields[f.index]
	if field.values != nil {
		return nil
	}
	var cmd tea.Cmd
	field.input, cmd = field.input.Update(msg)
	return cmd
}
func (f *tuiForm) filter() (tuiFilter, error) {
	value := func(i int) string { return strings.TrimSpace(f.fields[i].input.Value()) }
	choice := func(i int) string { return f.fields[i].values[f.fields[i].choice] }
	filter := tuiFilter{Severity: choice(formSeverity), Client: value(formClient), Rule: value(formRule), Service: choice(formService), Keyword: value(formKeyword)}
	var since, until time.Time
	if text := value(formSince); text != "" {
		t, err := parseTUISince(text, f.now())
		if err != nil {
			return filter, fmt.Errorf("时间从 %w", err)
		}
		since, filter.Since = t, t.UTC().Format(indexTimeFormat)
	}
	if text := value(formUntil); text != "" {
		t, err := parseTUISince(text, f.now())
		if err != nil {
			return filter, fmt.Errorf("时间到 %w", err)
		}
		until, filter.Until = t, t.UTC().Format(indexTimeFormat)
	}
	if !since.IsZero() && !until.IsZero() && !until.After(since) {
		return filter, errors.New("时间到 需要晚于时间从")
	}
	return filter, nil
}
func (f *tuiForm) view(height int) string {
	lines := []string{tuiAccent.Render("筛选"), ""}
	compact := height < 17
	for i, field := range f.fields {
		if compact && i != f.index {
			continue
		}
		label := tuiCell(field.label, 10)
		if i == f.index {
			label = tuiAccent.Render(label)
		} else {
			label = tuiMuted.Render(label)
		}
		if field.values == nil {
			lines = append(lines, label+field.input.View())
			continue
		}
		options := []string{}
		for j, name := range field.names {
			if j == field.choice {
				options = append(options, tuiAccent.Render("["+tuiLine(name)+"]"))
			} else {
				options = append(options, tuiMuted.Render(" "+tuiLine(name)+" "))
			}
		}
		lines = append(lines, label+strings.Join(options, " "))
	}
	if compact {
		lines = append(lines, tuiMuted.Render(fmt.Sprintf("字段 %d/%d", f.index+1, len(f.fields))))
	}
	lines = append(lines, "")
	for _, field := range []struct {
		index       int
		name, after string
	}{{formSince, "时间从", " 起"}, {formUntil, "时间到", " 止"}} {
		text := strings.TrimSpace(f.fields[field.index].input.Value())
		if text == "" {
			continue
		}
		if t, err := parseTUISince(text, f.now()); err == nil {
			lines = append(lines, tuiMuted.Render(field.name+" = "+t.Local().Format("2006-01-02 15:04:05 MST")+field.after))
		} else {
			lines = append(lines, tuiWarn.Render(field.name+" "+err.Error()))
		}
	}
	lines = append(lines, tuiMuted.Render("级别按「不低于」筛选；规则和级别需要同一条告警同时满足"))
	if f.err != "" {
		lines = append(lines, tuiDanger.Render(f.err))
	}
	return strings.Join(lines, "\n")
}
func (m *tuiModel) updateForm(msg tea.KeyPressMsg) tea.Cmd {
	f := m.form
	field := &f.fields[f.index]
	switch msg.String() {
	case "esc":
		m.form = nil
		return nil
	case "tab", "down":
		f.index = (f.index + 1) % len(f.fields)
		return f.focus()
	case "shift+tab", "up":
		f.index = (f.index + len(f.fields) - 1) % len(f.fields)
		return f.focus()
	case "left", "right":
		if field.values != nil {
			step := 1
			if msg.String() == "left" {
				step = len(field.values) - 1
			}
			field.choice = (field.choice + step) % len(field.values)
			return nil
		}
	case "ctrl+r":
		for i := range f.fields {
			f.fields[i].input.SetValue("")
			f.fields[i].choice = 0
		}
		f.err = ""
		return nil
	case "enter":
		filter, err := f.filter()
		if err != nil {
			f.err = err.Error()
			return nil
		}
		m.form = nil
		return m.applyFilter(filter)
	}
	return f.update(msg)
}

// parseTUISince accepts relative durations and local clock times as well as RFC3339.
func parseTUISince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	now = now.Local()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	switch strings.ToLower(s) {
	case "today", "今天":
		return midnight, nil
	case "yesterday", "昨天":
		return midnight.AddDate(0, 0, -1), nil
	}
	if strings.HasSuffix(s, "d") {
		var days int
		if _, err := fmt.Sscanf(s, "%dd", &days); err == nil && days > 0 && fmt.Sprintf("%dd", days) == s {
			return now.AddDate(0, 0, -days), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return now.Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	for _, layout := range []string{"01-02 15:04:05", "01-02 15:04"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.Local)
			if t.After(now) {
				t = t.AddDate(-1, 0, 0)
			}
			return t, nil
		}
	}
	for _, layout := range []string{"15:04:05", "15:04"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			t = time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.Local)
			if t.After(now) {
				t = t.AddDate(0, 0, -1)
			}
			return t, nil
		}
	}
	return time.Time{}, errors.New("无法识别，可填 30m、2h、1d、today、14:30、11-16 14:30 或 2026-11-11T10:00:00+08:00")
}
