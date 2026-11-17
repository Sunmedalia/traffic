package main

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestRulePrefilterPreservesMatchAndUnicodeSemantics(t *testing.T) {
	patterns := []string{`(?i)(alpha|beta)`, `(?i)K`, `(?i)s`, `(?:abc)?[0-9]+`, `(?:foo|[0-9]+)`, `x{0,3}y`, `(?:foo|bar)+baz`, `a.*b`, `(?:foo|bar){2}`, `^$`, `[a-z]+`, `(?i)(\$\(|` + "`" + `)[^)]*`, `(?i)世界`}
	for _, rule := range rules {
		patterns = append(patterns, rule.Pattern)
	}
	texts := []string{"", "normal", "alpha", "BETA", "K", "ſ", "世界", "123", "foobarbaz", "ayb", "%2527%2520or%25201%253D1", "UNION SELECT 1", "<img src=x onerror=alert(1)>", "${jndi:ldap://example/a}", "root:x:0:0:", string([]byte{255, 'K'})}
	for _, pattern := range patterns {
		rs := []Rule{{ID: "test", Version: 1, Severity: "high", Field: "request", Pattern: pattern}}
		if err := compileRules(rs); err != nil {
			t.Fatal(err)
		}
		for _, text := range texts {
			reference := rs[0]
			reference.requiredLiterals = nil
			if got, want := matchView(rs[0], text, "request"), matchView(reference, text, "request"); !reflect.DeepEqual(got, want) {
				t.Fatalf("prefilter changed %q on %q: %+v != %+v", pattern, text, got, want)
			}
		}
	}
}
func FuzzRulePrefilterNeverRejectsMatch(f *testing.F) {
	corpus := append([]Rule(nil), rules...)
	corpus = append(corpus, Rule{ID: "unicode", Version: 1, Severity: "high", Field: "request", Pattern: `(?i)(K|s|世界)`})
	if err := compileRules(corpus); err != nil {
		f.Fatal(err)
	}
	for _, text := range []string{"normal", "UNION SELECT 1", "Kſ世界", "%252e%252e%252f", "${jndi:ldap://x}", "root:x:0:0:"} {
		f.Add([]byte(text))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 32768 {
			return
		}
		text := string(data)
		for _, rule := range corpus {
			reference := rule
			reference.requiredLiterals = nil
			if got, want := matchView(rule, text, "request"), matchView(reference, text, "request"); !reflect.DeepEqual(got, want) {
				t.Fatalf("changed match %q on %q", rule.Pattern, text)
			}
		}
	})
}
func BenchmarkDetectionViews(b *testing.B) {
	if err := loadRules(""); err != nil {
		b.Fatal(err)
	}
	old := noDetect
	noDetect = false
	defer func() { noDetect = old }()
	for _, payload := range []string{strings.Repeat("normal-x", 128), strings.Repeat("normal%2520", 90)} {
		record := Transaction{URL: "/api/echo", Request: []byte(fmt.Sprintf("POST /api/echo HTTP/1.1\r\nHost: test\r\nContent-Length: %d\r\n\r\n%s", len(payload), payload)), Response: []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(payload), payload))}
		b.Run(fmt.Sprint(len(payload)), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if len(detect(record)) != 0 {
					b.Fatal("normal traffic alerted")
				}
			}
		})
	}
}
