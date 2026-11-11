package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func nginxUID() (int, error) {
	uids := map[int]bool{}
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, dir := range dirs {
		cmd, e := os.ReadFile(filepath.Join(dir, "cmdline"))
		if e != nil || !strings.Contains(string(cmd), "nginx: worker") {
			continue
		}
		status, e := os.ReadFile(filepath.Join(dir, "status"))
		if e != nil {
			continue
		}
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				uid, e := strconv.Atoi(fields[1])
				if e == nil {
					uids[uid] = true
				}
			}
		}
	}
	if len(uids) != 1 {
		return 0, fmt.Errorf("expected one Nginx worker UID, found %d; specify --pid", len(uids))
	}
	for uid := range uids {
		if uid == 0 {
			return 0, fmt.Errorf("root Nginx workers require explicit --pid")
		}
		return uid, nil
	}
	return 0, fmt.Errorf("no Nginx workers")
}
