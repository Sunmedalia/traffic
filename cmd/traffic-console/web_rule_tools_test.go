package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebRuleHitsAndRuleTest(t *testing.T) {
	writer := tuiTestStore(t)
	now := time.Now().UTC()
	sqli := []Alert{{Rule: "SQLI-001", Severity: "high", Field: "request", Match: "or 1=1"}}
	putTUITransaction(t, writer, Transaction{ID: "a", Time: now.Add(-time.Minute), Method: "GET", URL: "/login?u=' or 1=1", Request: []byte("GET /login?u='%20or%201=1 HTTP/1.1\r\nHost: demo\r\nUser-Agent: sqlmap/1.7\r\n\r\n"), Alerts: sqli})
	putTUITransaction(t, writer, Transaction{ID: "b", Time: now, Method: "GET", URL: "/x?id=1 or 1=1", Request: []byte("GET /x HTTP/1.1\r\n\r\n"), Alerts: sqli})
	putTUITransaction(t, writer, Transaction{ID: "c", Time: now, Method: "GET", URL: "/plain", Request: []byte("GET /plain HTTP/1.1\r\n\r\n")})
	web := newWebServer([]string{writer.dir}, "rule-tools-token", time.Second)
	defer web.close()
	server := httptest.NewServer(web.handler())
	defer server.Close()
	sid := webSessionID(writer.dir)

	status, data := ruleRequest(t, server, web.token, "GET", "/api/sessions/"+sid+"/rule-hits", nil)
	var hits struct {
		Hits    []webRuleHit `json:"hits"`
		Total   int          `json:"total"`
		Alerted int          `json:"alerted"`
	}
	if err := json.Unmarshal(data, &hits); err != nil || status != 200 || hits.Total != 3 || hits.Alerted != 2 || len(hits.Hits) != 1 {
		t.Fatalf("rule hits %d %s", status, data)
	}
	if hit := hits.Hits[0]; hit.Rule != "SQLI-001" || hit.Requests != 2 || hit.Severity != "high" || hit.First >= hit.Last {
		t.Fatalf("bad hit %+v", hit)
	}
	if status, _ = ruleRequest(t, server, "wrong", "GET", "/api/sessions/"+sid+"/rule-hits", nil); status != 401 {
		t.Fatal("rule hits did not require a token", status)
	}

	custom := "- id: UA-001\n  version: 1\n  severity: low\n  field: request.header.User-Agent\n  pattern: '(?i)sqlmap'\n- id: NEVER-001\n  version: 1\n  severity: low\n  field: url\n  pattern: never-here\n"
	type testResult struct {
		Source      string   `json:"source"`
		Alerts      []Alert  `json:"alerts"`
		Recorded    []Alert  `json:"recorded"`
		TotalRules  int      `json:"total_rules"`
		CustomRules []string `json:"custom_rules"`
	}
	run := func(input map[string]string) (int, testResult, []byte) {
		t.Helper()
		status, data := ruleRequest(t, server, web.token, "POST", "/api/rules/test", input)
		var result testResult
		if status == 200 {
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
		}
		return status, result, data
	}
	matched := func(result testResult, id string) bool {
		for _, alert := range result.Alerts {
			if alert.Rule == id {
				return true
			}
		}
		return false
	}
	status, result, data := run(map[string]string{"content": custom, "session_id": sid, "request_id": "a"})
	if status != 200 || result.Source != "session" || !matched(result, "UA-001") || !matched(result, "SQLI-001") || matched(result, "NEVER-001") || len(result.Recorded) != 1 || len(result.CustomRules) != 2 || result.TotalRules != len(builtinRules)+2 {
		t.Fatalf("session rule test %d %s", status, data)
	}
	// Bare newlines from a pasted message still reach header and body fields.
	status, result, data = run(map[string]string{"content": custom, "request": "GET /a HTTP/1.1\nHost: demo\nUser-Agent: SQLMap\n\n", "response": "HTTP/1.1 200 OK\n\nuid=0(root) gid=0(root)"})
	if status != 200 || result.Source != "manual" || !matched(result, "UA-001") || !matched(result, "RESPONSE-CMD-001") {
		t.Fatalf("manual rule test %d %s", status, data)
	}
	if status, result, data = run(map[string]string{"request": "GET /plain HTTP/1.1\n\n"}); status != 200 || len(result.Alerts) != 0 || len(result.CustomRules) != 0 {
		t.Fatalf("builtin-only clean test %d %s", status, data)
	}
	status, data = ruleRequest(t, server, web.token, "POST", "/api/rules/test", map[string]string{"request": "GET /a b HTTP/1.1\nUser-Agent: x\n\n"})
	if status != 400 {
		t.Fatalf("unencoded space in request line accepted %d %s", status, data)
	}
	status, data = ruleRequest(t, server, web.token, "POST", "/api/rules/test", map[string]string{"request": "GET /a HTTP/1.1\nbroken header line\n\n"})
	if status != 200 || !strings.Contains(string(data), "已按宽松方式解析") || !strings.Contains(string(data), "malformed_header_line") {
		t.Fatalf("unparsable request did not warn %d %s", status, data)
	}
	for _, input := range []map[string]string{
		{"content": "- id: broken", "request": "GET / HTTP/1.1\n\n"},
		{"request": "not a request line"},
		{"session_id": sid, "request_id": "missing"},
		{"session_id": sid},
	} {
		if status, _, data = run(input); status == 200 {
			t.Fatalf("invalid rule test accepted %v: %s", input, data)
		}
	}
	// Testing reads only: the stored alerts are unchanged.
	if status, data = ruleRequest(t, server, web.token, "GET", "/api/sessions/"+sid+"/rule-hits", nil); status != 200 || json.Unmarshal(data, &hits) != nil || len(hits.Hits) != 1 || hits.Hits[0].Requests != 2 {
		t.Fatalf("rule test changed stored alerts %s", data)
	}
}
