package main

import "fmt"

// checkMemoryBackedSession refuses a capture whose evidence would be written to
// RAM inside the collector's memory budget. Evidence there is charged to the
// cgroup and never reclaimed, so a session growing toward --disk-limit-mib gets
// the collector OOM-killed mid-capture: no drain, no final status, the session
// left marked running. Half the budget stays for the collector itself.
func checkMemoryBackedSession(dir string) error {
	kind, ok := memoryBackedFilesystem(dir)
	if !ok || diskLimitMiB <= collectorMemoryMiB/2 {
		return nil
	}
	return fmt.Errorf("会话目录 %s 位于内存文件系统（%s），写入的证据计入采集器 %d MiB 内存预算且无法回收，"+
		"会话增长到 --disk-limit-mib %d MiB 之前采集器就会被内核 OOM 终止；"+
		"请用 --data-dir 或 --output 指向磁盘目录，或将 --disk-limit-mib 设为不超过 %d",
		dir, kind, collectorMemoryMiB, diskLimitMiB, collectorMemoryMiB/2)
}
