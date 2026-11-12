package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWindowsProcessIdentity(t *testing.T) {
	first, err := processTarget("", os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	second, err := processIdentity("", os.Getpid())
	if err != nil || first.ID == "" || first.ID != second || first.PID != os.Getpid() {
		t.Fatalf("unstable process identity: %+v %q %v", first, second, err)
	}
	if _, err := processIdentity("", -1); err == nil {
		t.Fatal("invalid PID accepted")
	}
}

func TestIISBindingPorts(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SystemRoot", root)
	dir := filepath.Join(root, "System32", "inetsrv", "config")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	config := `<configuration><system.applicationHost><sites><site><bindings>
<binding protocol="http" bindingInformation="*:8080:" />
<binding protocol="https" bindingInformation="[::1]:8443:traffic-lab" />
<binding protocol="http" bindingInformation="127.0.0.1:8080:other" />
<binding protocol="net.tcp" bindingInformation="9000:*" />
</bindings></site></sites></system.applicationHost></configuration>`
	if err := os.WriteFile(filepath.Join(dir, "applicationHost.config"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if ports := iisPorts(); !reflect.DeepEqual(ports, []int{8080, 8443}) {
		t.Fatalf("IIS binding ports %v", ports)
	}
}
