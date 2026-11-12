package main

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func resourceLimitDescription() string { return "windows-job: 256MiB, 50% of one CPU" }

func limitResources() (func(), error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	cleanup := func() { windows.CloseHandle(job) }
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{JobMemoryLimit: 256 << 20}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_JOB_MEMORY
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		cleanup()
		return nil, err
	}
	// CPU rate is measured against all logical processors, in hundredths of a percent.
	cpu := struct{ Flags, Rate uint32 }{Flags: 1 | 4, Rate: uint32(5000 / runtime.NumCPU())}
	if cpu.Rate == 0 {
		cpu.Rate = 1
	}
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectCpuRateControlInformation, uintptr(unsafe.Pointer(&cpu)), uint32(unsafe.Sizeof(cpu))); err != nil {
		cleanup()
		return nil, err
	}
	if err = windows.AssignProcessToJobObject(job, windows.CurrentProcess()); err != nil {
		cleanup()
		return nil, err
	}
	return cleanup, nil
}
