package main

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Sunmedalia/traffic/internal/index"
)

func TestWebRequestFiltersDecodeExcludeParamAndStatic(t *testing.T) {
	writer := tuiTestStore(t)
	now := time.Now().UTC()
	for i, path := range []string{"/a?id=1%2520union%2520select", "/b?id=union+select", "/static/app.js?v=1", "/img/logo.PNG", "/c?cmd=ls&x=1", "/d?xcmd=1", "/e?flag&cmd"} {
		putTUITransaction(t, writer, Transaction{ID: string(rune('a' + i)), Time: now.Add(time.Duration(i) * time.Second), Host: "demo", Method: "GET", URL: path})
	}
	web := newWebServer([]string{writer.dir}, "filter-token", time.Second)
	defer web.close()
	server := httptest.NewServer(web.handler())
	defer server.Close()
	sid := webSessionID(writer.dir)
	query := func(params url.Values) (int, []string, string) {
		t.Helper()
		status, data := ruleRequest(t, server, web.token, "GET", "/api/sessions/"+sid+"/requests?"+params.Encode(), nil)
		var result struct {
			Rows []struct {
				ID string `json:"id"`
			} `json:"rows"`
		}
		if status == 200 {
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
		}
		ids := []string{}
		for _, row := range result.Rows {
			ids = append(ids, row.ID)
		}
		sort.Strings(ids)
		return status, ids, string(data)
	}
	cases := []struct {
		name   string
		params url.Values
		want   string
	}{
		{"stored text only", url.Values{"keyword": {"union select"}}, ""},
		{"one decoding round", url.Values{"keyword": {"union select"}, "decode": {"1"}}, "b"},
		{"decode then decode again", url.Values{"keyword": {"union select"}, "decode": {"2"}}, "a,b"},
		{"exclude terms with comma and space", url.Values{"exclude": {"static，logo  cmd"}}, "a,b"},
		{"exclusion sees decoded text", url.Values{"exclude": {"union select"}, "decode": {"2"}, "param": {"id"}}, ""},
		{"parameter name, not a suffix", url.Values{"param": {"cmd"}}, "e,g"},
		{"hide static assets case-insensitively", url.Values{"static": {"hide"}}, "a,b,e,f,g"},
	}
	for _, test := range cases {
		status, ids, data := query(test.params)
		if status != 200 || strings.Join(ids, ",") != test.want {
			t.Errorf("%s: got %d %v want %q (%s)", test.name, status, ids, test.want, data)
		}
	}
	for _, bad := range []url.Values{{"decode": {"9"}}, {"decode": {"x"}}, {"param": {"a=b"}}} {
		if status, _, data := query(bad); status != 400 {
			t.Errorf("invalid filter %v accepted: %d %s", bad, status, data)
		}
	}
	// Timeline and summary share the same filter, so counts stay consistent.
	status, data := ruleRequest(t, server, web.token, "GET", "/api/sessions/"+sid+"/summary?static=hide&decode=2&keyword=union%20select", nil)
	if status != 200 || !strings.Contains(string(data), `"total":2`) {
		t.Fatalf("summary ignored new filters: %d %s", status, data)
	}
}

func TestURLDecodeRoundsAndMalformedEscapes(t *testing.T) {
	cases := []struct {
		in     string
		rounds int
		want   string
	}{
		{"a%2520b", 1, "a%20b"},
		{"a%2520b", 2, "a b"},
		{"a+b%zz%41", 1, "a b%zzA"},
		{"%2525252525", 9, "%25"}, // capped at MaxURLDecodeRounds
		{"plain", 3, "plain"},
	}
	for _, c := range cases {
		if got := index.URLDecode(c.in, c.rounds); got != c.want {
			t.Errorf("URLDecode(%q,%d)=%q want %q", c.in, c.rounds, got, c.want)
		}
	}
}
