package session

import (
	"strings"
	"testing"
	"time"
)

func TestComputeIntegrityWarningsDetectsLegacyStalledSession(t *testing.T) {
	started := time.Date(2026, 11, 18, 2, 48, 59, 0, time.UTC)
	lastPkt := started.Add(190 * time.Millisecond)
	statusMod := started.Add(75 * time.Second)

	capture := Stats{
		Started:    started,
		State:      "stopped",
		Packets:    105,
		DrainState: "confirmed",
		GapCounts:  map[string]uint64{"pcap/drop_counter_unavailable/sources": 1},
		ProbeExits: map[string]ProbeExit{
			"6092:133000": {
				DataDrained:       true,
				HooksRemoved:      true,
				ScriptUnloaded:    false,
				TransportDetached: false,
				RuntimeState:      "inspect hooks, script and transport separately",
			},
		},
	}
	reconstructed := &Stats{
		Packets:       105,
		FirstPacketAt: started.Add(10 * time.Millisecond),
		LastPacketAt:  lastPkt,
	}

	warnings := ComputeIntegrityWarnings(capture, reconstructed, statusMod)
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{
		"收包时间提前中断",
		"当前抓包驱动（如 WinDivert）不公开内核队列丢包计数",
		"已恢复函数 Hook，但脚本或传输未完全从目标进程卸载",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing expected warning %q in:\n%s", want, joined)
		}
	}
}

func TestComputeIntegrityWarningsDetectsPollStallSendMismatchAndUnrestoredHooks(t *testing.T) {
	started := time.Date(2026, 11, 18, 3, 0, 0, 0, time.UTC)
	stopped := started.Add(30 * time.Second)
	capture := Stats{
		Started:                started,
		Stopped:                stopped,
		State:                  "stopped",
		Packets:                50,
		LastPacketAt:           stopped.Add(-time.Second),
		LastPacketPollAt:       stopped.Add(-12 * time.Second),
		ProbeReceiveMatches:    4,
		ProbeRecoveredReceives: 1,
		ProbeSendMatches:       9,
		ProbeExits: map[string]ProbeExit{
			"w3wp:1": {
				HookBased:    true,
				DataDrained:  false,
				HooksRemoved: false,
			},
		},
	}
	warnings := ComputeIntegrityWarnings(capture, nil, stopped)
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{
		"抓包读取线程疑似中途停滞",
		"至少遗漏 4 条请求明文",
		"未确认完成数据排空",
		"未确认恢复目标函数 Hook",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing expected warning %q in:\n%s", want, joined)
		}
	}
}

func TestComputeIntegrityWarningsQuietWhenHealthy(t *testing.T) {
	started := time.Date(2026, 11, 18, 4, 0, 0, 0, time.UTC)
	stopped := started.Add(30 * time.Second)
	capture := Stats{
		Started:                started,
		Stopped:                stopped,
		State:                  "stopped",
		Packets:                400,
		FirstPacketAt:          started.Add(100 * time.Millisecond),
		LastPacketAt:           stopped.Add(-200 * time.Millisecond),
		LastPacketPollAt:       stopped.Add(-50 * time.Millisecond),
		ProbeReceiveMatches:    18,
		ProbeRecoveredReceives: 2,
		ProbeSendMatches:       20,
		ProbeExits: map[string]ProbeExit{
			"w3wp:1": {
				HookBased:         true,
				DataDrained:       true,
				HooksRemoved:      true,
				ScriptUnloaded:    true,
				TransportDetached: true,
				RuntimeState:      "clean_detach",
			},
		},
	}
	if warnings := ComputeIntegrityWarnings(capture, nil, stopped); len(warnings) != 0 {
		t.Fatalf("unexpected warnings on healthy session: %v", warnings)
	}
}
