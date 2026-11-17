package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

func TestCommandHelpAndChineseExamples(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("ports", "80,443", "TCP ports")
	fs.String("duration", "0", "capture duration")
	for _, cn := range []bool{false, true} {
		var doctor, capture bytes.Buffer
		printCollectorHelp(&doctor, "doctor", cn, fs)
		printCollectorHelp(&capture, "capture", cn, fs)
		if strings.Contains(doctor.String(), "--duration") || !strings.Contains(capture.String(), "--duration") {
			t.Fatal("doctor and capture options were mixed")
		}
		for _, output := range []string{doctor.String(), capture.String()} {
			if !strings.Contains(output, "traffic ") {
				t.Fatal("missing runnable example")
			}
			if cn && !strings.Contains(output, "使用示例") {
				t.Fatal("missing Chinese help")
			}
		}
	}
	for _, args := range [][]string{{"--cn-help"}, {"help", "capture", "--cn-help"}, {"doctor", "--cn-help"}} {
		_, cn, ok := helpRequest(args)
		if !cn || !ok {
			t.Fatalf("Chinese help not recognized: %v", args)
		}
	}
	if _, _, ok := helpRequest([]string{"capture", "--name", "help"}); ok {
		t.Fatal("session name interpreted as help")
	}
	if err := run([]string{"doctor", "--duration", "2s"}); err == nil || !strings.Contains(err.Error(), "not a doctor option") {
		t.Fatalf("doctor accepted capture option: %v", err)
	}
}
