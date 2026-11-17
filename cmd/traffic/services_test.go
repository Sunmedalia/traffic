package main

import (
	"testing"
)

func TestServiceCLIValidation(t *testing.T) {
	for _, args := range [][]string{{"capture", "--pid", "-1"}, {"capture", "--java-pid", "3"}, {"capture", "--java-attach", "--pid", "1", "--java-pid", "2"}, {"capture", "--service", "invalid"}, {"capture", "--service", "openssl"}, {"capture", "--java-attach"}, {"capture", "--java-attach", "--pid", "1", "--no-tls"}} {
		if err := run(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
