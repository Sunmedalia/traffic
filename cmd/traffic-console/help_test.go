package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

func TestConsoleCommandHelpScopesAndExamples(t *testing.T) {
	fs := flag.NewFlagSet("help-test", flag.ContinueOnError)
	for _, name := range []string{"session", "rules", "rules-dir", "scan-window", "scan-paths", "alert-webhook", "allow-private-webhook", "listen", "out", "limit"} {
		fs.String(name, "", "test option")
	}
	for _, cn := range []bool{false, true} {
		var web, analyze, export bytes.Buffer
		printConsoleHelp(&web, "web", cn, fs)
		printConsoleHelp(&analyze, "analyze", cn, fs)
		printConsoleHelp(&export, "export", cn, fs)
		for _, expected := range []string{"--rules-dir", "--listen", "traffic-console web --data-dir", "1 MiB", "256"} {
			if !strings.Contains(web.String(), expected) {
				t.Fatalf("web help missing %q: %s", expected, web.String())
			}
		}
		if strings.Contains(web.String(), "--scan-paths") || strings.Contains(web.String(), "--alert-webhook") || strings.Contains(web.String(), "--allow-private-webhook") {
			t.Fatal("web help contains CLI analysis options")
		}
		for _, expected := range []string{"--rules ", "--scan-window", "--scan-paths", "--alert-webhook", "--allow-private-webhook", "analysis-current.json"} {
			if !strings.Contains(analyze.String(), expected) {
				t.Fatalf("analyze help missing %q: %s", expected, analyze.String())
			}
		}
		if strings.Contains(analyze.String(), "--rules-dir") || strings.Contains(analyze.String(), "--listen") {
			t.Fatal("analysis help contains web-only options")
		}
		if !strings.Contains(export.String(), "--out") || strings.Contains(export.String(), "--limit") {
			t.Fatal("export options mixed with queries")
		}
		if cn && !strings.Contains(web.String(), "规则与分析") {
			t.Fatal("missing Chinese rule management guidance")
		}
	}
}

func TestAllowPrivateWebhookFlagOnlyAppliesToAnalyze(t *testing.T) {
	if err := run([]string{"web", "--allow-private-webhook"}); err == nil || !strings.Contains(err.Error(), "requires traffic-console analyze") {
		t.Fatalf("web accepted the private webhook flag: %v", err)
	}
	if err := run([]string{"analyze", "--allow-private-webhook"}); err == nil || err.Error() != "--session required" {
		t.Fatalf("analyze rejected the private webhook flag: %v", err)
	}
}

func TestConsoleHelpEntryPointsDoNotRequireSessionsOrRuleFiles(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"--cn-help"}, {"help"}, {"help", "web", "--cn-help"}, {"web", "--help"}, {"web", "--cn-help"}, {"analyze", "--help"}, {"analyze", "--cn-help"}, {"rules", "--help"}, {"rules", "--cn-help"}, {"rules", "check", "--help"}, {"export", "--cn-help"}} {
		if err := run(args); err != nil {
			t.Fatalf("help entry %v failed: %v", args, err)
		}
	}
}
