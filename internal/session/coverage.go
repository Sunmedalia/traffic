package session

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// CoverageWarning also applies to sessions written before coverage metadata existed.
const CoverageWarning = "完整性未验证，启动及探针盲区漏采数未知。TLS 已知丢弃计数为已观测下限，0 不代表采全。"

// ComputeIntegrityWarnings derives actionable capture and probe integrity
// warnings from collector status, optional offline packet reconstruction, and
// the status file's modification timestamp (used as fallback end time for v0.1.3
// sessions written before Stopped existed).
func ComputeIntegrityWarnings(capture Stats, reconstructed *Stats, statusModTime time.Time) []string {
	var out []string
	seen := map[string]bool{}
	add := func(msg string) {
		msg = strings.TrimSpace(msg)
		if msg != "" && !seen[msg] {
			seen[msg] = true
			out = append(out, msg)
		}
	}
	for _, existing := range capture.IntegrityWarnings {
		add(existing)
	}

	endTime := capture.Stopped
	if endTime.IsZero() {
		if capture.State == "running" || capture.State == "starting" {
			endTime = time.Now().UTC()
		} else if !statusModTime.IsZero() {
			endTime = statusModTime.UTC()
		}
	}

	if !capture.LastPacketPollAt.IsZero() && !endTime.IsZero() {
		if lag := endTime.Sub(capture.LastPacketPollAt); lag >= 5*time.Second {
			add(fmt.Sprintf("抓包读取线程疑似中途停滞：最后轮询早于检查/停止时间 %s", lag.Round(100*time.Millisecond)))
		}
	}

	lastPacket := capture.LastPacketAt
	if lastPacket.IsZero() && reconstructed != nil && !reconstructed.LastPacketAt.IsZero() {
		lastPacket = reconstructed.LastPacketAt
	}
	packets := capture.Packets
	if reconstructed != nil && reconstructed.Packets > packets {
		packets = reconstructed.Packets
	}
	if packets > 0 && !capture.Started.IsZero() && !endTime.IsZero() && !lastPacket.IsZero() {
		sessionSpan := endTime.Sub(capture.Started)
		tailSilence := endTime.Sub(lastPacket)
		if sessionSpan >= 15*time.Second && tailSilence >= 10*time.Second && tailSilence*2 >= sessionSpan {
			add(fmt.Sprintf("收包时间提前中断：最后数据包早于停止时间 %s（会话总时长 %s），后半程可能漏采", tailSilence.Round(100*time.Millisecond), sessionSpan.Round(100*time.Millisecond)))
		}
	}

	for key, count := range capture.GapCounts {
		if count > 0 && strings.Contains(key, "drop_counter_unavailable") {
			add("当前抓包驱动（如 WinDivert）不公开内核队列丢包计数，dropped=0 不能排除内核层丢包")
			break
		}
	}

	capturedReq := capture.ProbeReceiveMatches + capture.ProbeRecoveredReceives
	if capture.ProbeSendMatches > capturedReq {
		add(fmt.Sprintf("IIS 探针收发计数失衡：响应完成 %d 次，但请求侧仅捕获/恢复 %d 次，至少遗漏 %d 条请求明文", capture.ProbeSendMatches, capturedReq, capture.ProbeSendMatches-capturedReq))
	}

	if len(capture.ProbeExits) > 0 {
		targets := make([]string, 0, len(capture.ProbeExits))
		for target := range capture.ProbeExits {
			targets = append(targets, target)
		}
		sort.Strings(targets)
		for _, target := range targets {
			exit := capture.ProbeExits[target]
			if !exit.DataDrained {
				add(fmt.Sprintf("探针 %s 停采时未确认完成数据排空", target))
			}
			if exit.HookBased || strings.Contains(exit.RuntimeState, "hooks") {
				if !exit.HooksRemoved {
					add(fmt.Sprintf("探针 %s 停采时未确认恢复目标函数 Hook", target))
				} else if !exit.ScriptUnloaded || !exit.TransportDetached {
					add(fmt.Sprintf("探针 %s 已恢复函数 Hook，但脚本或传输未完全从目标进程卸载（建议在合适窗口回收工作进程后再重复采集）", target))
				}
			}
		}
	}

	return out
}
