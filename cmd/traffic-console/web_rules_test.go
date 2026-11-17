package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const testManagedRules = "- id: LOCAL-001\n  version: 1\n  severity: high\n  field: url\n  pattern: local-marker\n"

func ruleRequest(t *testing.T, server *httptest.Server, token, method, path string, input any) (int, []byte) {
	t.Helper()
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, server.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, data
}

func TestWebRuleLibraryCRUDValidationAndBoundaries(t *testing.T) {
	web := newWebServer([]string{t.TempDir()}, "rules-test-token", time.Second)
	var err error
	web.ruleLibrary, err = openRuleLibrary(filepath.Join(t.TempDir(), "rules"))
	if err != nil {
		t.Fatal(err)
	}
	defer web.close()
	server := httptest.NewServer(web.handler())
	defer server.Close()
	call := func(method, path string, input any) (int, []byte) {
		return ruleRequest(t, server, web.token, method, path, input)
	}
	if status, _ := ruleRequest(t, server, "wrong", http.MethodPut, "/api/rules/local.yaml", map[string]string{"content": testManagedRules}); status != 401 {
		t.Fatal("rule writes did not require a token", status)
	}
	for _, text := range []string{"", "[]", "- id: broken", testManagedRules + "---\n[]\n", strings.Replace(testManagedRules, "local-marker", "[", 1), strings.Replace(testManagedRules, "LOCAL-001", "SQLI-001", 1), strings.Repeat("x", maxRuleBytes+1)} {
		if status, data := call("POST", "/api/rules/validate", map[string]string{"content": text}); status != 422 {
			t.Fatalf("invalid rule accepted: %d %s", status, data)
		}
	}
	status, data := call("PUT", "/api/rules/local.yaml", map[string]string{"content": testManagedRules})
	var saved ruleFile
	if err = json.Unmarshal(data, &saved); err != nil || status != 200 || !saved.Valid || saved.Count != 1 || saved.Revision == "" {
		t.Fatalf("save failed: %d %s", status, data)
	}
	if info, err := os.Stat(filepath.Join(web.ruleLibrary.dir, "local.yaml")); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) {
		t.Fatal("rule file permissions", info, err)
	}
	if status, data = call("GET", "/api/rules/local.yaml", nil); status != 200 || !bytes.Contains(data, []byte("local-marker")) {
		t.Fatalf("read failed: %d %s", status, data)
	}
	if status, data = call("GET", "/api/rules", nil); status != 200 || !bytes.Contains(data, []byte(web.ruleLibrary.dir)) || !bytes.Contains(data, []byte("local.yaml")) {
		t.Fatalf("listing failed: %d %s", status, data)
	}
	for _, revision := range []string{"", "stale"} {
		if status, _ = call("PUT", "/api/rules/local.yaml", map[string]string{"content": testManagedRules, "revision": revision}); status != 409 {
			t.Fatal("overwrote concurrent edits", status)
		}
		if status, _ = call("DELETE", "/api/rules/local.yaml", map[string]string{"revision": revision}); status != 409 {
			t.Fatal("deleted concurrent edits", status)
		}
	}
	if status, _ = call("PUT", "/api/rules/local.yaml", map[string]string{"content": "bad yaml", "revision": saved.Revision}); status != 422 {
		t.Fatal("invalid replacement saved", status)
	}
	original, _ := os.ReadFile(filepath.Join(web.ruleLibrary.dir, "local.yaml"))
	if string(original) != testManagedRules {
		t.Fatal("failed validation modified file")
	}
	if status, _ = call("PUT", "/api/rules/local.yaml", map[string]string{"content": strings.Replace(testManagedRules, "local-marker", "updated-marker", 1), "revision": saved.Revision}); status != 200 {
		t.Fatal("valid replacement failed", status)
	}
	if status, _ = call("DELETE", "/api/rules/local.yaml", map[string]string{"revision": saved.Revision}); status != 409 {
		t.Fatal("stale delete accepted", status)
	}
	_, data = call("GET", "/api/rules/local.yaml", nil)
	if err = json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if status, _ = call("DELETE", "/api/rules/local.yaml", map[string]string{"revision": saved.Revision}); status != 200 {
		t.Fatal("delete failed", status)
	}
	if status, _ = call("GET", "/api/rules/local.yaml", nil); status != 404 {
		t.Fatal("deleted file visible", status)
	}
	for _, name := range []string{"../outside.yaml", "/absolute.yaml", "bad\\file.yaml", "CON.yaml", "a.txt", ".hidden.yaml", "a.yaml:stream", "a%2fyaml", "a.yaml\n"} {
		if validRuleFilename(name) {
			t.Fatal("unsafe filename accepted", name)
		}
	}
	if runtime.GOOS != "windows" {
		outside := filepath.Join(t.TempDir(), "outside.yaml")
		if err = os.WriteFile(outside, []byte(testManagedRules), 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Symlink(outside, filepath.Join(web.ruleLibrary.dir, "link.yaml")); err != nil {
			t.Fatal(err)
		}
		if status, _ = call("GET", "/api/rules/link.yaml", nil); status == 200 {
			t.Fatal("read symlink outside rule directory")
		}
		if status, _ = call("PUT", "/api/rules/link.yaml", map[string]string{"content": testManagedRules}); status == 200 {
			t.Fatal("wrote symlink outside rule directory")
		}
	}
}

func TestWebAnalyzesWithManagedRuleSnapshotAndRefreshesReaders(t *testing.T) {
	writer := tuiTestStore(t)
	putTUITransaction(t, writer, Transaction{ID: "local", Time: time.Now(), URL: "/local-marker", Method: "GET"})
	web := newWebServer([]string{writer.dir}, "analysis-rule-token", time.Second)
	var err error
	web.ruleLibrary, err = openRuleLibrary(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer web.close()
	server := httptest.NewServer(web.handler())
	defer server.Close()
	sid := webSessionID(writer.dir)
	path := "/api/sessions/" + sid
	if status, data := ruleRequest(t, server, web.token, "GET", path+"/requests?alerts=1", nil); status != 200 || !bytes.Contains(data, []byte(`"count":0`)) {
		t.Fatalf("initial query %d %s", status, data)
	}
	if status, data := ruleRequest(t, server, web.token, "PUT", "/api/rules/local.yaml", map[string]string{"content": testManagedRules}); status != 200 {
		t.Fatalf("rule create %d %s", status, data)
	}
	start := func(file string) webAnalysisJob {
		t.Helper()
		status, data := ruleRequest(t, server, web.token, "POST", path+"/analyze", map[string]string{"rules_file": file})
		if status != 202 {
			t.Fatalf("start failed %d %s", status, data)
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			status, data = ruleRequest(t, server, web.token, "GET", "/api/analysis", nil)
			var response struct {
				Job webAnalysisJob `json:"job"`
			}
			if err = json.Unmarshal(data, &response); err != nil || status != 200 {
				t.Fatalf("status failed %d %s", status, data)
			}
			if response.Job.State != "running" {
				return response.Job
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("analysis did not finish")
		return webAnalysisJob{}
	}
	job := start("local.yaml")
	if job.State != "succeeded" || job.Report == nil || job.Report.Alerts != 1 {
		t.Fatalf("bad analysis %+v", job)
	}
	if status, data := ruleRequest(t, server, web.token, "GET", path+"/requests?alerts=1&rule=LOCAL-001", nil); status != 200 || !bytes.Contains(data, []byte(`"count":1`)) {
		t.Fatalf("cached reader did not refresh %d %s", status, data)
	}
	var source []byte
	if err = writer.db.QueryRow("SELECT data FROM requests WHERE id='local'").Scan(&source); err != nil || bytes.Contains(source, []byte("LOCAL-001")) {
		t.Fatal("local analysis changed captured evidence", err)
	}
	job = start("")
	if job.State != "succeeded" || job.Report.Alerts != 0 {
		t.Fatalf("builtin-only reanalysis retained custom rule %+v", job)
	}
	if status, data := ruleRequest(t, server, web.token, "GET", path+"/requests?alerts=1", nil); status != 200 || !bytes.Contains(data, []byte(`"count":0`)) {
		t.Fatalf("stale analysis visible %d %s", status, data)
	}
	if status, _ := ruleRequest(t, server, web.token, "DELETE", "/api/analysis", map[string]string{"id": job.ID}); status != 409 {
		t.Fatal("cancelled completed task", status)
	}
	if status, _ := ruleRequest(t, server, web.token, "POST", path+"/analyze", map[string]string{"rules_file": "../outside.yaml"}); status != 400 {
		t.Fatal("analysis accepted outside rules", status)
	}
}
