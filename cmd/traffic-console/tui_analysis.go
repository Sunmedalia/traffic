package main

// The analysis dialog mirrors the web 分析 dialog: pick the built-in rules or
// a file from the rule directory, start, watch and stop the job, and see this
// session's recent runs. A job keeps running while the dialog is closed.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
)

type tuiAnalysisJob struct {
	id              int
	rules, state    string
	started, finish time.Time
	err             string
	report          *analysisReport
	cancel          context.CancelFunc
}
type tuiAnalysis struct {
	open       bool
	files      []string
	loadErr    string
	choice     int
	err        string
	job        *tuiAnalysisJob
	history    []*tuiAnalysisJob
	cancelling bool
	nextID     int
}
type tuiAnalysisTick struct{}
type tuiAnalysisDone struct {
	ID     int
	Report analysisReport
	Err    error
}

var tuiJobStates = map[string]string{"running": "分析中", "succeeded": "已完成", "failed": "失败", "cancelled": "已停止"}

func (m tuiModel) analysisRunning() bool {
	return m.analysis != nil && m.analysis.job != nil && m.analysis.job.state == "running"
}

func (m *tuiModel) analysisTick() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return tuiAnalysisTick{} })
}

// ruleFiles lists the rule directory without creating it.
func (m *tuiModel) ruleFiles() ([]string, error) {
	if m.rulesDir == "" {
		return nil, nil
	}
	if _, err := os.Stat(m.rulesDir); os.IsNotExist(err) {
		return nil, nil
	}
	library, err := openRuleLibrary(m.rulesDir)
	if err != nil {
		return nil, err
	}
	defer library.root.Close()
	files, err := library.list()
	if err != nil {
		return nil, err
	}
	names := make([]string, len(files))
	for i, f := range files {
		names[i] = f.Name
	}
	return names, nil
}

func (m *tuiModel) openAnalysis() tea.Cmd {
	if m.analysis == nil {
		m.analysis = &tuiAnalysis{}
	}
	a := m.analysis
	wanted := ""
	if a.choice > 0 && a.choice <= len(a.files) {
		wanted = a.files[a.choice-1]
	}
	a.open, a.err, a.loadErr = true, "", ""
	files, err := m.ruleFiles()
	if err != nil {
		a.loadErr = "读取规则目录失败：" + cleanTUIText(err.Error())
	}
	a.files, a.choice = files, 0
	for i, name := range files {
		if name == wanted {
			a.choice = i + 1
		}
	}
	return nil
}

// analysisBlocked explains why a new job cannot start, as the web dialog does.
func (m tuiModel) analysisBlocked() string {
	switch m.snapshot.Stats.State {
	case "running", "starting":
		return "采集仍在进行，停止采集后即可分析。"
	}
	if m.analysisRunning() {
		return "分析正在进行，同一时间只能运行一个任务。"
	}
	return ""
}

func (m *tuiModel) updateAnalysis(key string) tea.Cmd {
	a := m.analysis
	switch key {
	case "esc", "A":
		a.open = false
		return nil
	case "up", "k":
		a.choice = (a.choice + len(a.files)) % (len(a.files) + 1)
	case "down", "j", "tab":
		a.choice = (a.choice + 1) % (len(a.files) + 1)
	case "x":
		if m.analysisRunning() && !a.cancelling {
			a.cancelling = true
			a.job.cancel()
		}
	case "enter":
		return m.startAnalysis()
	}
	return nil
}

func (m *tuiModel) startAnalysis() tea.Cmd {
	a := m.analysis
	if reason := m.analysisBlocked(); reason != "" {
		a.err = reason
		return nil
	}
	rulesFile := ""
	var rs []Rule
	var err error
	if a.choice > 0 {
		rulesFile = a.files[a.choice-1]
		library, openErr := openRuleLibrary(m.rulesDir)
		if openErr != nil {
			a.err = cleanTUIText(openErr.Error())
			return nil
		}
		file, readErr := library.read(rulesFile)
		library.root.Close()
		if readErr != nil {
			a.err = "读取规则失败：" + cleanTUIText(readErr.Error())
			return nil
		}
		rs, err = validateRuleContent(file.Content)
	} else {
		rs, err = rulesFromYAML(nil)
	}
	if err != nil {
		a.err = "规则无效：" + cleanTUIText(err.Error())
		return nil
	}
	a.err, a.cancelling = "", false
	a.nextID++
	ctx, cancel := context.WithCancel(m.ctx)
	job := &tuiAnalysisJob{id: a.nextID, rules: rulesFile, state: "running", started: time.Now(), cancel: cancel}
	a.job = job
	a.history = append([]*tuiAnalysisJob{job}, a.history...)
	if len(a.history) > 10 {
		a.history = a.history[:10]
	}
	dir, id := m.store.dir, job.id
	run := func() tea.Msg {
		defer cancel()
		report, err := analyzeSessionRules(ctx, dir, "", rs, time.Minute, 20)
		return tuiAnalysisDone{ID: id, Report: report, Err: err}
	}
	return tea.Batch(run, m.analysisTick())
}

func (m *tuiModel) finishAnalysis(msg tuiAnalysisDone) tea.Cmd {
	a := m.analysis
	if a == nil {
		return nil
	}
	var job *tuiAnalysisJob
	for _, j := range a.history {
		if j.id == msg.ID {
			job = j
		}
	}
	if job == nil || job.state != "running" {
		return nil
	}
	job.finish = time.Now()
	a.cancelling = false
	switch {
	case errors.Is(msg.Err, context.Canceled):
		job.state = "cancelled"
		m.flash = "分析已停止，会话保留上次完整的分析结果"
	case msg.Err != nil:
		job.state, job.err = "failed", cleanTUIText(msg.Err.Error())
		m.flash = "分析失败：" + job.err
	default:
		job.state, job.report = "succeeded", &msg.Report
		m.flash = fmt.Sprintf("分析完成，%s 条告警", tuiCount(msg.Report.Alerts))
		if warning := tuiScanLimitWarning(job.report); warning != "" {
			m.flash = warning + " · " + m.flash
		}
		m.summary, m.overview, m.timeline = nil, nil, nil
		m.stale = !m.details
		return m.refreshNow()
	}
	return nil
}

func tuiScanLimitWarning(report *analysisReport) string {
	if report == nil || report.ScanSkipped == nil {
		return ""
	}
	skipped := report.ScanSkipped
	return fmt.Sprintf("SCAN-001 超限，跳过 %s 条事务，可能漏报", tuiCount(skipped.Clients+skipped.Paths))
}

func tuiJobElapsed(job *tuiAnalysisJob) string {
	end := job.finish
	if job.state == "running" {
		end = time.Now()
	}
	seconds := int(max(0, end.Sub(job.started).Round(time.Second).Seconds()))
	if seconds < 60 {
		return fmt.Sprintf("%d 秒", seconds)
	}
	return fmt.Sprintf("%d 分 %d 秒", seconds/60, seconds%60)
}
func tuiJobRules(job *tuiAnalysisJob) string {
	if job.rules == "" {
		return "仅内置规则"
	}
	return "内置 + " + job.rules
}
func tuiJobState(state string) string {
	label := tuiJobStates[state]
	switch state {
	case "running":
		return tuiAccent.Render("● " + label)
	case "succeeded":
		return tuiGood.Render("✓ " + label)
	case "failed":
		return tuiDanger.Render("✕ " + label)
	}
	return tuiMuted.Render("○ " + label)
}

func (m tuiModel) analysisView(height int) string {
	a := m.analysis
	title := m.title
	if title == "" && m.store != nil {
		title = m.store.dir
	}
	lines := []string{tuiAccent.Render("分析会话"), tuiLine(title)}
	if job := a.job; job != nil && job.state == "succeeded" {
		if warning := tuiScanLimitWarning(job.report); warning != "" {
			lines = append(lines, tuiWarn.Render(warning))
		}
	}
	lines = append(lines, tuiMuted.Render("分析成功后更新当前会话的告警。停止分析会保留上次完整结果。"), "", tuiBold.Render("规则"))
	options := append([]string{"仅内置规则"}, a.files...)
	for i, name := range options {
		if i > 0 {
			name = "内置 + " + name
		}
		line := "  " + tuiLine(name)
		if i == a.choice {
			line = tuiSelected.Render("▸ " + tuiLine(name))
		}
		lines = append(lines, tuiHit(fmt.Sprintf("arule:%d", i), tuiCell(line, max(1, m.width))))
	}
	if m.rulesDir != "" {
		lines = append(lines, tuiMuted.Render("规则目录 "+tuiLine(m.rulesDir)))
	}
	if a.loadErr != "" {
		lines = append(lines, tuiDanger.Render(a.loadErr))
	}
	if reason := m.analysisBlocked(); reason != "" && !m.analysisRunning() {
		lines = append(lines, tuiWarn.Render(reason))
	}
	if a.err != "" {
		lines = append(lines, tuiDanger.Render(a.err))
	}
	if job := a.job; job != nil {
		lines = append(lines, "", tuiJobState(job.state)+tuiMuted.Render(fmt.Sprintf("  %s · %s 开始 · 用时 %s", tuiJobRules(job), tuiFormatTime(job.started, ""), tuiJobElapsed(job))))
		switch job.state {
		case "running":
			status := "正在重建并检测会话中的请求…  x 停止分析"
			if a.cancelling {
				status = "正在停止…"
			}
			lines = append(lines, tuiAccent.Render(status))
		case "succeeded":
			r := job.report
			alerts := tuiCount(r.Alerts) + " 告警命中"
			if r.Alerts > 0 {
				alerts = tuiDanger.Render(alerts)
			}
			lines = append(lines, fmt.Sprintf("%s 事务 · %s · %d 条规则  %s", tuiCount(r.Transactions), alerts, len(r.Rules), tuiMuted.Render("按 3 查看告警")))
		case "failed":
			lines = append(lines, tuiDanger.Render(tuiLine(job.err)))
		case "cancelled":
			lines = append(lines, tuiMuted.Render("已停止，会话保留上次完整的分析结果。"))
		}
	}
	buttons := []string{}
	if m.analysisBlocked() == "" {
		buttons = append(buttons, tuiButton("enter", "开始分析"))
	}
	if m.analysisRunning() && !a.cancelling {
		buttons = append(buttons, tuiButton("x", "停止分析"))
	}
	lines = append(lines, "", strings.Join(append(buttons, tuiButton("esc", "关闭")), "  "))
	if len(a.history) > 1 {
		lines = append(lines, "", tuiBold.Render("此会话的最近任务"), tuiMuted.Render(tuiCell("开始", 14)+tuiCell("规则", 24)+tuiCell("结果", 10)+tuiCell("事务", 10)+tuiCell("告警", 8)+"耗时"))
		for _, job := range a.history[1:] {
			transactions, alerts := "—", "—"
			if job.report != nil {
				transactions, alerts = tuiCount(job.report.Transactions), tuiCount(job.report.Alerts)
			}
			lines = append(lines, tuiCell(tuiFormatTime(job.started, "dayclock"), 14)+tuiCell(tuiLine(tuiJobRules(job)), 24)+tuiCell(tuiJobStates[job.state], 10)+tuiCell(transactions, 10)+tuiCell(alerts, 8)+tuiJobElapsed(job))
		}
	}
	if len(lines) > height {
		lines = lines[:height]
	}
	return strings.Join(lines, "\n")
}
