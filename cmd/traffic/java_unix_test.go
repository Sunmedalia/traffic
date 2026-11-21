//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestJavaJarLaunch(t *testing.T) {
	for cmd, want := range map[string]bool{
		"java -jar app.jar": true,
		"/opt/jdk/bin/java -Xmx1g -Dserver.port=8443 -jar a": true,
		"java -cp -jar Main":                         false,
		"java -cp lib/* com.example.Main -jar x.jar": false,
		"java -jar":                            false,
		"java --module-path mods -jar app.jar": true,
	} {
		if got := javaJarLaunch(strings.Fields(cmd)); got != want {
			t.Errorf("%q: got %v", cmd, got)
		}
	}
}

func TestProcessTargetRecognizesJavaJar(t *testing.T) {
	root := t.TempDir()
	for pid, p := range map[int]struct{ exe, cmd string }{
		21: {"/opt/jdk8/jre/bin/java", "java\x00-Xmx512m\x00-jar\x00/srv/app.jar\x00--server.port=8443\x00"},
		22: {"/opt/jdk8/jre/bin/java", "java\x00-cp\x00app.jar\x00com.example.Worker\x00"},
	} {
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		fields := make([]string, 20)
		for i := range fields {
			fields[i] = "0"
		}
		fields[19] = "99"
		for name, body := range map[string]string{"stat": strconv.Itoa(pid) + " (java) " + strings.Join(fields, " "), "status": "Uid:\t1000\t0\t0\t0\nGid:\t1000\t0\t0\t0\n", "cmdline": p.cmd} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(p.exe, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	if target, err := processTarget(root, 21); err != nil || target.Service != "tomcat" {
		t.Fatalf("java -jar target %+v %v", target, err)
	}
	if target, err := processTarget(root, 22); err != nil || target.Service != "unknown" {
		t.Fatalf("plain JVM target %+v %v", target, err)
	}
}

func TestJavaAttachCommandSelectsAttachAPI(t *testing.T) {
	proc := t.TempDir()
	touch := func(path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	target := func(pid int, exe string) {
		t.Helper()
		dir := filepath.Join(proc, strconv.Itoa(pid))
		if err := os.MkdirAll(filepath.Join(dir, "root"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	// JDK 17 target: module image present.
	target(31, "/jdk17/bin/java")
	touch(filepath.Join(proc, "31/root/jdk17/lib/modules"))
	helper, args, err := javaAttachCommand(proc, 31, "", "/a.jar")
	if err != nil || helper != filepath.Join(proc, "31/exe") || !reflect.DeepEqual(args, []string{"--add-modules", "jdk.attach", "-cp", "/a.jar"}) {
		t.Fatalf("jdk17 %s %v %v", helper, args, err)
	}
	// JDK 8 running jre/bin/java: tools.jar is one level above the JRE.
	target(32, "/jdk8/jre/bin/java")
	touch(filepath.Join(proc, "32/root/jdk8/lib/tools.jar"))
	_, args, err = javaAttachCommand(proc, 32, "", "/a.jar")
	if err != nil || !reflect.DeepEqual(args, []string{"-cp", "/a.jar:" + filepath.Join(proc, "32/root/jdk8/lib/tools.jar")}) {
		t.Fatalf("jdk8 jre %v %v", args, err)
	}
	// JDK 8 running bin/java.
	target(33, "/jdk8b/bin/java")
	touch(filepath.Join(proc, "33/root/jdk8b/lib/tools.jar"))
	_, args, err = javaAttachCommand(proc, 33, "", "/a.jar")
	if err != nil || !reflect.DeepEqual(args, []string{"-cp", "/a.jar:" + filepath.Join(proc, "33/root/jdk8b/lib/tools.jar")}) {
		t.Fatalf("jdk8 bin %v %v", args, err)
	}
	// A JDK 8 JRE has no attach API and must be reported instead of failing later.
	target(34, "/jre8/bin/java")
	if _, _, err = javaAttachCommand(proc, 34, "", "/a.jar"); err == nil || !strings.Contains(err.Error(), "tools.jar") {
		t.Fatalf("jre8 %v", err)
	}
	// An explicit helper is resolved on the collector's own filesystem.
	jdk := t.TempDir()
	touch(filepath.Join(jdk, "lib/tools.jar"))
	touch(filepath.Join(jdk, "bin/java"))
	helper, args, err = javaAttachCommand(proc, 34, filepath.Join(jdk, "bin/java"), "/a.jar")
	if err != nil || helper != filepath.Join(jdk, "bin/java") || !reflect.DeepEqual(args, []string{"-cp", "/a.jar:" + filepath.Join(jdk, "lib/tools.jar")}) {
		t.Fatalf("explicit %s %v %v", helper, args, err)
	}
}
