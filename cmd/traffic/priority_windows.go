package main

import "golang.org/x/sys/windows"

// Windows has priority classes instead of nice values. Any positive value
// selects BELOW_NORMAL, which child helpers (Python/Frida) inherit; the Frida
// agents themselves run on the target's own threads and are not affected. A
// process already at BELOW_NORMAL or IDLE keeps its class: this only ever
// lowers priority.
func lowerCollectorPriority(nice int) error {
	if nice == 0 {
		return nil
	}
	process := windows.CurrentProcess()
	if current, err := windows.GetPriorityClass(process); err == nil &&
		(current == windows.BELOW_NORMAL_PRIORITY_CLASS || current == windows.IDLE_PRIORITY_CLASS) {
		return nil
	}
	return windows.SetPriorityClass(process, windows.BELOW_NORMAL_PRIORITY_CLASS)
}
