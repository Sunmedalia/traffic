package main

import (
	"strings"
	"testing"
)

func TestDiskReserveScalesForCaptureOnly(t *testing.T) {
	oldMin, oldScaled := minFreeMiB, scaledDiskReserve
	defer func() { minFreeMiB, scaledDiskReserve = oldMin, oldScaled }()
	const gib = uint64(1) << 30
	minFreeMiB, scaledDiskReserve = 0, true
	for _, c := range []struct{ total, want uint64 }{
		{4 * gib, 512 << 20},   // small disks keep the former floor
		{40 * gib, 2 * gib},    // 5%
		{1000 * gib, 10 * gib}, // capped
	} {
		if got := diskReserveBytes(c.total); got != c.want {
			t.Fatalf("capture reserve for %d GiB = %d MiB, want %d MiB", c.total/gib, got>>20, c.want>>20)
		}
	}
	scaledDiskReserve = false
	if got := diskReserveBytes(1000 * gib); got != 512<<20 {
		t.Fatalf("import reserve = %d MiB", got>>20)
	}
	minFreeMiB = 2048
	if got := diskReserveBytes(4 * gib); got != 2048<<20 {
		t.Fatalf("explicit reserve = %d MiB", got>>20)
	}
}

func TestProtectionFlagsAreBounded(t *testing.T) {
	oldNice, oldMin := collectorNice, minFreeMiB
	defer func() { collectorNice, minFreeMiB = oldNice, oldMin }()
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"capture", "--no-tls", "--collector-nice", "20"}, "--collector-nice"},
		{[]string{"capture", "--no-tls", "--collector-nice", "-1"}, "--collector-nice"},
		{[]string{"capture", "--no-tls", "--min-free-mib", "100"}, "--min-free-mib"},
	} {
		err := run(append(c.args, "--output", t.TempDir()+"/session"))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%v: %v", c.args, err)
		}
	}
	if err := run([]string{"doctor", "--collector-nice", "5"}); err == nil || !strings.Contains(err.Error(), "not a doctor option") {
		t.Fatalf("doctor accepted --collector-nice: %v", err)
	}
}

func TestCollectorPriorityZeroKeepsInherited(t *testing.T) {
	old := collectorNice
	defer func() { collectorNice = old }()
	collectorNice = 0
	s := &Store{}
	if got := applyCollectorPriority(s); got != "priority inherited" || len(s.stats.Errors) != 0 {
		t.Fatalf("priority %q, errors %v", got, s.stats.Errors)
	}
}
