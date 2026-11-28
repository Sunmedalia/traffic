package main

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
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
		"uid=0(root) gid=0(root)", "<!ENTITY x SYSTEM \"a\">", "filename=\"a.php\"", "filename= a.phtml", "/shell.php5",
		// Non-ASCII text: matches beside UTF-8, through the two runes that
		// case-fold to ASCII letters (ſ, K), and around invalid or truncated
		// sequences that start like them.
		"张三' or 1=1", "UNION ſELECT 1", "ſleep(5)", "benchmarK(1)", "<ſcript>", "“union select”", "中文 root:x:0:0:",
		"${Kava} $(whoami)", "\xff\xfe union\xe2\x84 select", "union \xc5select", "x\xe2\x84\xabk", "\xc5\xbeſ", "\xe2\x84", "\xc5",
		"中<img src=x onerror=alert(1)>文", "uid=0(root) gid=0(根)", "\xe2\x84\xaa\xc5\xbf\xe2\x84\xaa"}
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
	view := decodedView{text: form, folded: foldForPrefilter(form)}
	for _, rule := range rs {
		if (rule.ID == "SQLI-001" || rule.ID == "CMD-001") && rule.mayMatch(view) {
			t.Errorf("%s prefilter admits an ordinary form post", rule.ID)
		}
	}
}

// Chinese pages and forms are UTF-8 throughout. The prefilters must reject
// ordinary content there too, instead of handing every rule to RE2.
func TestRulePrefilterRejectsOrdinaryUTF8(t *testing.T) {
	rs := append([]Rule(nil), rules...)
	if err := compileRules(rs); err != nil {
		t.Fatal(err)
	}
	request := "POST /api/order HTTP/1.1\r\nHost: shop\r\nContent-Type: application/json\r\n\r\n{\"name\":\"张三\",\"city\":\"北京\",\"note\":\"普通订单备注…“引号”\"}"
	response := "<html><body><p>欢迎访问我们的网站，这里是普通的页面内容。</p></body></html>"
	for _, rule := range rs {
		text := request
		switch {
		case rule.Field == "url":
			continue
		case strings.HasPrefix(rule.Field, "response"):
			text = response
		}
		if rule.mayMatch(decodedView{text: text, folded: foldForPrefilter(text)}) {
			t.Errorf("%s prefilter admits ordinary UTF-8 text %q", rule.ID, text)
		}
	}
}

// foldRunes is foldForPrefilter decoded rune by rune, the way RE2 reads text.
func foldRunes(text string) string {
	var out strings.Builder
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		switch {
		case r == '\u017f':
			out.WriteByte('s')
		case r == '\u212a':
			out.WriteByte('k')
		case r < utf8.RuneSelf:
			out.WriteRune(unicode.ToLower(r))
		default:
			out.WriteString(text[i : i+size])
		}
		i += size
	}
	return out.String()
}

func TestFoldForPrefilter(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", ""}, {"union select", "union select"}, {"UNION Select", "union select"},
		{"\u017f", "s"}, {"\u212a", "k"}, {"中文\u212a\u017fB", "中文ksb"},
		// Truncated sequences, and other runes that start like ſ or K, stay.
		{"\xe2\x84", "\xe2\x84"}, {"\xc5", "\xc5"}, {"\xe2\x84\xab", "\xe2\x84\xab"}, {"\xc5\xbe", "\xc5\xbe"}, {"\xe2\xe2\x84\xaa", "\xe2k"}, {"“\u212a”", "“k”"},
		// Output chunk boundaries.
		{strings.Repeat("A", 4095) + "\u212aB", strings.Repeat("a", 4095) + "kb"}, {strings.Repeat("A", 8192), strings.Repeat("a", 8192)},
	} {
		if got := foldForPrefilter(c.in); got != c.want || got != foldRunes(c.in) {
			t.Errorf("foldForPrefilter(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Text that folding leaves as it is needs no copy.
	text := `{"name":"张三","city":"北京"}`
	if allocs := testing.AllocsPerRun(10, func() { _ = foldForPrefilter(text) }); allocs != 0 {
		t.Errorf("unchanged text allocated %v times", allocs)
	}
}

// Prefilter literals are lowercase ASCII, and RE2 folds case with
// unicode.SimpleFold. Folding must therefore map every rune whose fold orbit
// holds an ASCII letter; this fails if a Unicode update adds one.
func TestFoldForPrefilterCoversCaseFolding(t *testing.T) {
	for r := rune(utf8.RuneSelf); r <= unicode.MaxRune; r++ {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < utf8.RuneSelf {
				if got, want := foldForPrefilter(string(r)), string(unicode.ToLower(f)); got != want {
					t.Errorf("%U folds to %q for prefilters, want %q", r, got, want)
				}
				break
			}
		}
	}
}

func FuzzFoldForPrefilter(f *testing.F) {
	for _, text := range []string{"UNION \u017fELECT", "\u212a\xe2\x84", "\xc5\xc5\xbf", "中文“\u212a”"} {
		f.Add([]byte(text))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if got, want := foldForPrefilter(string(data)), foldRunes(string(data)); got != want {
			t.Fatalf("foldForPrefilter(%q) = %q, want %q", data, got, want)
		}
	})
}

func FuzzRulePrefilterNeverRejectsMatch(f *testing.F) {
	corpus := append([]Rule(nil), rules...)
	corpus = append(corpus, Rule{ID: "unicode", Version: 1, Severity: "high", Field: "request", Pattern: `(?i)(K|s|世界)`})
	if err := compileRules(corpus); err != nil {
		f.Fatal(err)
	}
	for _, text := range []string{"normal", "UNION SELECT 1", "Kſ世界", "%252e%252e%252f", "${jndi:ldap://x}", "root:x:0:0:", "张' or 1=1", "UNION \u017fELECT 1", "benchmar\u212a(1)", "\xe2\x84\xaa\xc5\xbf<\u017fcript>"} {
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
	binary := make([]byte, 16<<10)
	rand.New(rand.NewSource(1)).Read(binary)
	for _, c := range []struct {
		name, payload string
		// mayAlert: random bytes can hold two backticks, which CMD-001 reports.
		mayAlert bool
	}{
		{"1024", strings.Repeat("normal-x", 128), false},
		{"990", strings.Repeat("normal%2520", 90), false},
		{"utf8-json", strings.Repeat(`{"name":"张三","city":"北京","note":"普通订单备注内容"},`, 32), false},
		{"binary-16k", string(binary), true},
	} {
		payload := c.payload
		record := Transaction{URL: "/api/echo", Request: []byte(fmt.Sprintf("POST /api/echo HTTP/1.1\r\nHost: test\r\nContent-Length: %d\r\n\r\n%s", len(payload), payload)), Response: []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(payload), payload))}
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(record.Request) + len(record.Response)))
			for i := 0; i < b.N; i++ {
				if len(detect(record)) != 0 && !c.mayAlert {
					b.Fatal("normal traffic alerted")
				}
			}
		})
	}
}

func TestPrefilterStringSetMatchesContains(t *testing.T) {
	sets := [][]string{{"union\t", "union "}, {"0(", "1(", "9("}, {"a", "b", ";"}, {"ab", "cd"}, {"x", "xy"}, {"aa", "aaa"}, {"xab", "yab"}, {"ab", "zzab"}}
	texts := []string{"", "a", "union", "union x", "xunion\tselect", "((0(", "(9", "9", ";", "zzcd", "xy", "aaaa", "abab", "a(1(", "cdab", "zabyab", "abzab", "zab", "ab", "zzab"}
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
