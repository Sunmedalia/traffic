//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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
		t.Fatal("non-root workers should share one library probe")
	}
	apache[0].UID = 0
	if groupFor(apache[0]).PID != 12 {
		t.Fatal("root probe must target PID")
	}
}

func TestListeningSnapshotSharesNamespaceButRefreshesPorts(t *testing.T) {
	root := t.TempDir()
	for _, pid := range []string{"10", "20"} {
		dir := filepath.Join(root, pid)
		for _, sub := range []string{"net", "ns", "fd"} {
			if err := os.MkdirAll(filepath.Join(dir, sub), 0700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink("net:[shared]", filepath.Join(dir, "ns/net")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("socket:[123]", filepath.Join(dir, "fd/3")); err != nil {
			t.Fatal(err)
		}
	}
	table := func(port string) []byte { return []byte("0: 0100007F:" + port + " 00000000:0000 0A 0 0 0 0 0 123\n") }
	if err := os.WriteFile(filepath.Join(root, "10/net/tcp"), table("01BB"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "20/net/tcp"), table("0050"), 0600); err != nil {
		t.Fatal(err)
	}
	snapshots := map[string]map[string]int{}
	first := listeningPortsSnapshot(root, filepath.Join(root, "10"), snapshots)
	second := listeningPortsSnapshot(root, filepath.Join(root, "20"), snapshots)
	if len(first) != 1 || first[0] != 443 || len(second) != 1 || second[0] != 443 {
		t.Fatal("namespace not shared", first, second)
	}
	fresh := listeningPortsSnapshot(root, filepath.Join(root, "20"), map[string]map[string]int{})
	if len(fresh) != 1 || fresh[0] != 80 {
		t.Fatal("discovery retained stale namespace ports", fresh)
	}
	if err := os.Remove(filepath.Join(root, "20/ns/net")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("net:[different]", filepath.Join(root, "20/ns/net")); err != nil {
		t.Fatal(err)
	}
	isolated := listeningPortsSnapshot(root, filepath.Join(root, "20"), snapshots)
	if len(isolated) != 1 || isolated[0] != 80 {
		t.Fatal("namespaces mixed", isolated)
	}
}
