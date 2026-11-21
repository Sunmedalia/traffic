package main

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	termansi "github.com/charmbracelet/x/ansi"
)

func TestTUIScanLimitWarningFitsAndPersists(t *testing.T) {
	m := tuiDetailModel(t)
	m.Update(tea.WindowSizeMsg{Width: 40, Height: 24})
	job := &tuiAnalysisJob{id: 1, state: "running"}
	m.analysis = &tuiAnalysis{open: true, job: job, history: []*tuiAnalysisJob{job}}
	m.finishAnalysis(tuiAnalysisDone{ID: job.id, Report: analysisReport{
		ScanSkipped: &scanSkipped{Clients: 3, Paths: 7},
	}})
	const warning = "SCAN-001 超限，跳过 10 条事务，可能漏报"
	if got := termansi.Strip(termansi.Truncate(m.noticeLine(), m.width, "…")); !strings.Contains(got, warning) {
		t.Fatalf("scan warning hidden in footer: %q", got)
	}
	m.flash = ""
	if frame := termansi.Strip(m.View().Content); !strings.Contains(frame, warning) {
		t.Fatalf("scan warning missing from analysis panel: %q", frame)
	}
}
