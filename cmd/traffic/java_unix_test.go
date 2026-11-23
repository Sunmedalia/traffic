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
		"java --enable-native-access ALL-UNNAMED -jar app.jar":                                        true,
		"java --enable-native-access=ALL-UNNAMED -jar app.jar":                                        true,
		"java --upgrade-module-path mods --add-reads app=other --patch-module app=patch -jar app.jar": true,
		"java --module=app/Main -jar argument.jar":                                                    false,
	} {
		if got := javaJarLaunch(strings.Fields(cmd)); got != want {
			t.Errorf("%q: got %v", cmd, got)
		}
	}
}

func TestProcessTargetRecognizesJavaJar(t *testing.T) {
	root := t.TempDir()
	for pid, p := range map[int]struct{ uid, cmd string }{
		21: {"1000", "java\x00-Xmx512m\x00-jar\x00/srv/app.jar\x00--server.port=8443\x00"},
		22: {"1000", "java\x00-cp\x00app.jar\x00com.example.Worker\x00"},
		23: {"0", "java\x00org.apache.catalina.startup.Bootstrap\x00"},
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
		for name, body := range map[string]string{"stat": strconv.Itoa(pid) + " (java) " + strings.Join(fields, " "), "status": "Uid:\t" + p.uid + "\nGid:\t" + p.uid + "\n", "cmdline": p.cmd} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink("/opt/jdk8/jre/bin/java", filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	if target, err := processTarget(root, 21); err != nil || target.Service != "tomcat" {
		t.Fatalf("java -jar target %+v %v", target, err)
	}
	if target, err := processTarget(root, 22); err != nil || target.Service != "unknown" {
		t.Fatalf("plain JVM target %+v %v", target, err)
	}
	if targets := discoverTargets(root, "auto", 0, 0, ""); len(targets) != 1 || targets[0].PID != 21 {
		t.Fatalf("auto discovery did not prefer the non-root JVM: %+v", targets)
	}
	if targets := discoverTargets(root, "auto", 0, 23, ""); len(targets) != 2 || targets[0].PID != 21 || targets[1].PID != 23 {
		t.Fatalf("auto discovery lost the explicitly requested JVM: %+v", targets)
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
	java := filepath.Join(jdk, "bin/java")
	touch(java)
	if err := os.Chmod(java, 0700); err != nil {
		t.Fatal(err)
	}
	resolvedJDK, err := filepath.EvalSymlinks(jdk)
	if err != nil {
		t.Fatal(err)
	}
	wantArgs := []string{"-cp", "/a.jar" + string(os.PathListSeparator) + filepath.Join(resolvedJDK, "lib/tools.jar")}
	helper, args, err = javaAttachCommand(proc, 34, java, "/a.jar")
	if err != nil || helper != java || !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("explicit %s %v %v", helper, args, err)
	}

	bin := t.TempDir()
	pathJava := filepath.Join(bin, "java")
	if err := os.Symlink(java, pathJava); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	helper, args, err = javaAttachCommand(proc, 34, "java", "/a.jar")
	if err != nil || helper != pathJava || !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("PATH helper %s %v %v", helper, args, err)
	}
}
