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
	texts := []string{"", "normal", "alpha", "BETA", "K", "ſ", "世界", "123", "foobarbaz", "ayb", "%2527%2520or%25201%253D1", "UNION SELECT 1", "<img src=x onerror=alert(1)>", "${jndi:ldap://example/a}", "root:x:0:0:", string([]byte{255, 'K'}),
		// Adjacency around optional, repeated and zero-width parts.
		"1 or 1=1", "1 OR '1'='1'", "x or\t2 = 2", "union\tall  select", "unionselect", "sleep (5)", "benchmark(1,2)",
		"a;id", "a; \tid", "a&cat=3", "a|cat /etc/x", "x=1&id", "$(id)", "`id`", "${ jndi:ldap:", "${jndi :rmi:",
		"< script>", "<img onload =x>", "javascript :x", "http://127.0.0.1/", "https://localhost", "gopher://x",
		"uid=0(root) gid=0(root)", "<!ENTITY x SYSTEM \"a\">", "filename=\"a.php\"", "filename= a.phtml", "/shell.php5"}
	for _, pattern := range patterns {
		rs := []Rule{{ID: "test", Version: 1, Severity: "high", Field: "request", Pattern: pattern}}
		if err := compileRules(rs); err != nil {
			t.Fatal(err)
		}
		for _, text := range texts {
			reference := rs[0]
			reference.prefilter = nil
			if got, want := matchView(rs[0], text, "request"), matchView(reference, text, "request"); !reflect.DeepEqual(got, want) {
				t.Fatalf("prefilter changed %q on %q: %+v != %+v", pattern, text, got, want)
			}
		}
	}
}

// Ordinary form posts contain "or", "&", spaces and "cat" (in "application"),
// but not the contiguous runs SQLI-001 and CMD-001 require.
func TestRulePrefilterRejectsOrdinaryForms(t *testing.T) {
	rs := append([]Rule(nil), rules...)
	if err := compileRules(rs); err != nil {
		t.Fatal(err)
	}
	form := "POST /api/item HTTP/1.1\r\nHost: demo\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1&b=hello world&order=desc&color=red"
	folded, _ := foldedASCII(form)
	view := decodedView{text: form, folded: folded, ascii: true}
	for _, rule := range rs {
		if (rule.ID == "SQLI-001" || rule.ID == "CMD-001") && rule.mayMatch(view) {
			t.Errorf("%s prefilter admits an ordinary form post", rule.ID)
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
			reference.prefilter = nil
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

func TestPrefilterStringSetMatchesContains(t *testing.T) {
	sets := [][]string{{"union\t", "union "}, {"0(", "1(", "9("}, {"a", "b", ";"}, {"ab", "cd"}, {"x", "xy"}, {"aa", "aaa"}}
	texts := []string{"", "a", "union", "union x", "xunion\tselect", "((0(", "(9", "9", ";", "zzcd", "xy", "aaaa", "abab", "a(1(", "cdab"}
	for _, values := range sets {
		set := newStringSet(values)
		for _, text := range texts {
			want := false
			for _, value := range values {
				want = want || strings.Contains(text, value)
			}
			if got := set.occursIn(text); got != want {
				t.Errorf("%q in %q = %t, want %t", values, text, got, want)
			}
		}
	}
}
