package main

// Filter form and relative time parsing.

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

type tuiFormField struct {
	label, note string
	values      []string
	names       []string
	choice      int
	input       textinput.Model
}
type tuiForm struct {
	fields []tuiFormField
	index  int
	err    string
	now    func() time.Time
	// The original bounds are kept while their text is unchanged, so a range
	// picked on the timeline keeps its sub-second, exclusive end.
	origin               tuiFilter
	sinceText, untilText string
}

// The fields follow the web filter bar: the keyword first, then the quick
// choices, then the conditions behind "更多条件".
const (
	formKeyword = iota
	formDecode
	formSeverity
	formStatus
	formMethod
	formStatic
	formExclude
	formParam
	formCode
	formClient
	formRule
	formService
	formSince
	formUntil
)

var tuiMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

func tuiChoice(label string, values, names []string, current string) tuiFormField {
	field := tuiFormField{label: label, values: values, names: names}
	for i, v := range values {
		if v == current {
			field.choice = i
		}
	}
	return field
}

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
			return tuiIn(t).Format("2006-01-02 15:04:05")
		}
		return ""
	}
	since, until := local(f.Since), local(f.Until)
	form := &tuiForm{now: time.Now, origin: f, sinceText: since, untilText: until}
	statusClass, statusCode := f.Status, ""
	if f.Status != "" && f.Status != "pending" && !strings.HasSuffix(f.Status, "xx") {
		statusClass, statusCode = "", f.Status
	}
	methods := append([]string{""}, tuiMethods...)
	if f.Method != "" && !slices.Contains(methods, f.Method) {
		methods = append(methods, f.Method)
	}
	methodNames := append([]string{"全部"}, methods[1:]...)
	decodeValues, decodeNames := []string{"0"}, []string{"匹配原文"}
	for i := 1; i <= maxFilterDecodeRounds; i++ {
		decodeValues = append(decodeValues, fmt.Sprint(i))
		decodeNames = append(decodeNames, fmt.Sprintf("解码 %d 次", i))
	}
	static := "show"
	if f.HideStatic {
		static = "hide"
	}
	form.fields = []tuiFormField{
		text("关键词", "Host 或 URL 包含的文字", f.Keyword),
		tuiChoice("匹配方式", decodeValues, decodeNames, fmt.Sprint(f.Decode)),
		tuiChoice("级别", []string{"", "high", "medium", "low"}, []string{"全部", "仅高", "中及以上", "低及以上"}, f.Severity),
		tuiChoice("响应状态", []string{"", "2xx", "3xx", "4xx", "5xx", "pending"}, []string{"全部", "2xx", "3xx", "4xx", "5xx", "待响应"}, statusClass),
		tuiChoice("方法", methods, methodNames, f.Method),
		tuiChoice("静态资源", []string{"show", "hide"}, []string{"显示", "隐藏"}, static),
		text("排除关键词", "空格或逗号分隔，如 healthz .png", f.Exclude),
		text("包含参数", "参数名，如 cmd", f.Param),
		text("状态码", "具体状态码，如 403；填写后优先于响应状态", statusCode),
		text("来源地址", "IP 或 IP:端口", f.Client),
		text("规则 ID", "例如 SQLI-001", f.Rule),
		tuiChoice("服务", append([]string{""}, services...), append([]string{"全部"}, services...), f.Service),
		text("开始时间", "30m、2h、1d、today、14:30、11-16 14:30 或 RFC3339", since),
		text("结束时间", "留空表示到现在，格式同上", until),
	}
	form.fields[formDecode].note = "关键词和排除词先对 URL 解码若干次再匹配"
	form.fields[formStatic].note = "隐藏 js、css、图片、字体等静态资源请求"
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
	filter := tuiFilter{
		Keyword: value(formKeyword), Severity: choice(formSeverity), Status: choice(formStatus), Method: choice(formMethod),
		HideStatic: choice(formStatic) == "hide", Exclude: value(formExclude), Param: value(formParam),
		Client: value(formClient), Rule: value(formRule), Service: choice(formService),
	}
	filter.Decode, _ = strconv.Atoi(choice(formDecode))
	if code := value(formCode); code != "" {
		n, err := strconv.Atoi(code)
		if err != nil || n < 100 || n > 999 {
			return filter, errors.New("状态码需要是 100 到 999 之间的数字")
		}
		filter.Status = code
	}
	if len(excludeTerms(filter.Exclude)) > 20 {
		return filter, errors.New("排除关键词最多 20 个")
	}
	if strings.ContainsAny(filter.Param, "=&?#") {
		return filter, errors.New("参数名不能包含 = & ? #")
	}
	var since, until time.Time
	if text := value(formSince); text != "" {
		if text == f.sinceText && f.origin.Since != "" {
			filter.Since = f.origin.Since
			since, _ = time.Parse(indexTimeFormat, filter.Since)
		} else {
			t, err := parseTUISince(text, f.now())
			if err != nil {
				return filter, fmt.Errorf("开始时间 %w", err)
			}
			since, filter.Since = t, t.UTC().Format(indexTimeFormat)
		}
	}
	if text := value(formUntil); text != "" {
		if text == f.untilText && f.origin.Until != "" {
			filter.Until, filter.UntilExclusive = f.origin.Until, f.origin.UntilExclusive
			until, _ = time.Parse(indexTimeFormat, filter.Until)
		} else {
			t, err := parseTUISince(text, f.now())
			if err != nil {
				return filter, fmt.Errorf("结束时间 %w", err)
			}
			until, filter.Until = t, t.UTC().Format(indexTimeFormat)
		}
	}
	if !since.IsZero() && !until.IsZero() && !until.After(since) {
		return filter, errors.New("结束时间需要晚于开始时间")
	}
	return filter, nil
}
func (f *tuiForm) view(height int) string {
	lines := []string{tuiAccent.Render("筛选") + tuiMuted.Render(fmt.Sprintf("  第 %d/%d 项", f.index+1, len(f.fields))), ""}
	notes := []string{}
	for _, field := range []struct {
		index       int
		name, after string
	}{{formSince, "开始时间", " 起"}, {formUntil, "结束时间", " 止"}} {
		text := strings.TrimSpace(f.fields[field.index].input.Value())
		if text == "" {
			continue
		}
		if t, err := parseTUISince(text, f.now()); err == nil {
			notes = append(notes, tuiMuted.Render(field.name+" = "+tuiIn(t).Format("2006-01-02 15:04:05 MST")+field.after))
		} else {
			notes = append(notes, tuiWarn.Render(field.name+" "+err.Error()))
		}
	}
	if note := f.fields[f.index].note; note != "" {
		notes = append(notes, tuiMuted.Render(note))
	} else {
		notes = append(notes, tuiMuted.Render("级别按「不低于」筛选；规则和级别需要同一条告警同时满足"))
	}
	if f.err != "" {
		notes = append(notes, tuiDanger.Render(f.err))
	}
	// Show the window of fields around the focused one that fits above the notes.
	visible := max(1, height-len(lines)-len(notes)-3)
	start := max(0, min(f.index-visible/2, len(f.fields)-visible))
	for i := start; i < min(len(f.fields), start+visible); i++ {
		field := f.fields[i]
		label := tuiCell(field.label, 12)
		if i == f.index {
			label = tuiAccent.Render(label)
		} else {
			label = tuiMuted.Render(label)
		}
		label = tuiHit(fmt.Sprintf("ffield:%d", i), label)
		if field.values == nil {
			lines = append(lines, label+tuiHit(fmt.Sprintf("ffield:%d", i), field.input.View()))
			continue
		}
		options := []string{}
		for j, name := range field.names {
			option := tuiMuted.Render(" " + tuiLine(name) + " ")
			if j == field.choice {
				option = tuiAccent.Render("[" + tuiLine(name) + "]")
			}
			options = append(options, tuiHit(fmt.Sprintf("fopt:%d:%d", i, j), option))
		}
		lines = append(lines, label+strings.Join(options, " "))
	}
	lines = append(lines, "", tuiButton("enter", "应用")+"  "+tuiButton("ctrl+r", "清空")+"  "+tuiButton("esc", "取消"))
	return strings.Join(append(lines, notes...), "\n")
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
	now = tuiIn(now)
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, tuiZone())
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
		if t, err := time.ParseInLocation(layout, s, tuiZone()); err == nil {
			return t, nil
		}
	}
	for _, layout := range []string{"01-02 15:04:05", "01-02 15:04"} {
		if t, err := time.ParseInLocation(layout, s, tuiZone()); err == nil {
			t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, tuiZone())
			if t.After(now) {
				t = t.AddDate(-1, 0, 0)
			}
			return t, nil
		}
	}
	for _, layout := range []string{"15:04:05", "15:04"} {
		if t, err := time.ParseInLocation(layout, s, tuiZone()); err == nil {
			t = time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), t.Second(), 0, tuiZone())
			if t.After(now) {
				t = t.AddDate(0, 0, -1)
			}
			return t, nil
		}
	}
	return time.Time{}, errors.New("无法识别，可填 30m、2h、1d、today、14:30、11-16 14:30 或 2026-11-11T10:00:00+08:00")
}
