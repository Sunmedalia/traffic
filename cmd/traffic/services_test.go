package main

import (
	"encoding/json"
	"github.com/Sunmedalia/traffic/internal/session"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestServiceDiscoveryAndPIDIdentity(t *testing.T) {
	root := t.TempDir()
	for _, p := range []struct {
		pid       int
		name, cmd string
		uid       int
	}{{11, "nginx", "nginx: worker process", 33}, {12, "apache2", "apache2 -f test", 33}, {13, "java", "java org.apache.catalina.startup.Bootstrap", 1000}, {14, "python", "python app.py", 1000}} {
		dir := filepath.Join(root, strconv.Itoa(p.pid))
		if err := os.MkdirAll(filepath.Join(dir, "fd"), 0700); err != nil {
			t.Fatal(err)
		}
		fields := make([]string, 20)
		for i := range fields {
			fields[i] = "0"
		}
		fields[0] = "S"
		fields[19] = "1234"
		files := map[string]string{"stat": strconv.Itoa(p.pid) + " (name with ) brackets) " + strings.Join(fields, " "), "status": "Uid:\t" + strconv.Itoa(p.uid) + "\t0\t0\t0\n", "cmdline": p.cmd, "maps": "1000-2000 r-xp 0 00:01 1 /usr/lib/libssl.so.3\n"}
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink("/usr/bin/"+p.name, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	all := discoverTargets(root, "auto", 0, "")
	if len(all) != 3 {
		t.Fatalf("targets %+v", all)
	}
	apache := discoverTargets(root, "apache", 0, "")
	if len(apache) != 1 || apache[0].ID != "12:1234" || apache[0].UID != 33 {
		t.Fatalf("apache %+v", apache)
	}
	generic := discoverTargets(root, "openssl", 14, "/custom/libssl.so")
	if len(generic) != 1 || generic[0].Service != "openssl" || generic[0].Library != "/custom/libssl.so" {
		t.Fatalf("generic %+v", generic)
	}
	if groupFor(apache[0]).PID != 0 {
		t.Fatal("non-root workers should share probe")
	}
	apache[0].UID = 0
	if groupFor(apache[0]).PID != 12 {
		t.Fatal("root probe must target PID")
	}
}

func TestServiceCLIValidation(t *testing.T) {
	for _, args := range [][]string{{"capture", "--pid", "-1"}, {"capture", "--java-pid", "3"}, {"capture", "--java-attach", "--pid", "1", "--java-pid", "2"}, {"capture", "--service", "invalid"}, {"capture", "--service", "openssl"}, {"capture", "--java-attach"}, {"capture", "--java-attach", "--pid", "1", "--no-tls"}} {
		if err := run(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestPlainHTTPAttributionRequiresLocalAddress(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	s.stats.Targets = []session.Target{{Service: "apache", Ports: []int{80}}}
	for _, sample := range []struct{ id, endpoint, want string }{{"local", "127.0.0.1:80", "apache"}, {"remote", "203.0.113.20:80", ""}} {
		record := Transaction{ID: sample.id, Time: time.Now(), LocalEndpoint: sample.endpoint, URL: "/"}
		if err = s.save(record); err != nil {
			t.Fatal(err)
		}
		if err = s.restore(&record); err != nil {
			t.Fatal(err)
		}
		if record.Service != sample.want {
			t.Fatalf("%s attributed to %q", sample.endpoint, record.Service)
		}
	}
}

func TestJavaEventGapIsPreserved(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	p := newHTTP(s)
	frames := &Frames{}
	frames.ingest("read", []byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n"), frameContext{connection: "java:target:1", client: "127.0.0.1:1000", incomplete: true, local: "127.0.0.1:8443"}, false, p)
	var data []byte
	if err = s.db.QueryRow("SELECT data FROM requests").Scan(&data); err != nil {
		t.Fatal(err)
	}
	var record Transaction
	if err = json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if !record.Incomplete || record.LocalEndpoint != "127.0.0.1:8443" || s.stats.TLSDropped != 1 {
		t.Fatalf("lost gap metadata: %+v %+v", record, s.stats)
	}
}
