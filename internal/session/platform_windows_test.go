package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestEvidenceACLInheritance(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := RestrictDirectory(dir); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "request.http")
	if err := os.WriteFile(file, []byte("private evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, file} {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		acl := sd.String()
		if strings.Contains(acl, ";;;WD)") || strings.Contains(acl, ";;;BU)") || strings.Contains(acl, ";;;AU)") {
			t.Fatalf("broad evidence access on %s: %s", path, acl)
		}
		if !strings.Contains(acl, ";;;SY)") || !strings.Contains(acl, ";;;BA)") {
			t.Fatalf("missing inherited service access on %s: %s", path, acl)
		}
	}
}
