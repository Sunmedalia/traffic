package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Sunmedalia/traffic/internal/session"
	"github.com/google/gopacket/pcap"
)

// Keep the diagnostic JSON independent of presentation: automation explicitly
// opts into the existing schema with --json.
func writeDoctorReport(w io.Writer, report map[string]any, ports string) error {
	var out strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&out, format+"\n", args...) }
	text := func(key string) string { value, _ := report[key].(string); return value }
	yes := func(key string) bool { value, _ := report[key].(bool); return value }
	windows := text("os") == "windows"
	system := map[string]string{"windows": "Windows", "linux": "Linux", "darwin": "macOS"}[text("os")]
	if system == "" {
		system = text("os")
	}
	privilege := "普通用户"
	if yes("administrator") {
		privilege = "管理员"
	} else if yes("root") {
		privilege = "root"
	}
	line("\n  TRAFFIC · 环境自检")
	line("  %s / %s · %s", system, text("arch"), privilege)
	line("  只读检查，不开始采集或附加目标进程")
	line("\n  ── 网络采集 ────────────────────────────")
	if yes("administrator") || yes("root") {
		line("  [已具备] 采集所需的管理员 / root 身份")
	} else {
		line("  [需权限] 实际采集请使用管理员终端或 root 身份")
	}
	switch text("packet_backend") {
	case "windivert-sniff":
		line("  [已选择] WinDivert · 只读旁路采集")
		line("  [已发现] 随包驱动库")
		line("           %s", doctorSafe(text("bundled_packet_driver")))
		line("  [待验证] 驱动能否加载需在 capture 时确认")
		line("  [无需安装] Npcap（当前使用随包 WinDivert）")
		line("  [未知]   后端不提供队列丢包计数；不表示已发生丢包")
	case "npcap":
		line("  [已选择] Npcap · 实际抓包能力需在 capture 时确认")
	default:
		line("  [已选择] libpcap · 实际抓包能力需在 capture 时确认")
	}
	devices, _ := report["interfaces"].([]pcap.Interface)
	line("\n  ── 网络接口 · %d 项 ─────────────────────", len(devices))
	if len(devices) == 0 {
		line("  未发现网络接口，请检查系统网络配置。")
	}
	for _, device := range devices {
		label := device.Description
		if device.Name == "windivert" {
			label = "全部本机接口及回环"
		}
		if label == "" {
			label = device.Name
		}
		line("  %s", doctorSafe(label))
		if label != device.Name {
			line("    接口  %s", doctorSafe(device.Name))
		}
		var addresses []string
		for _, address := range device.Addresses {
			if address.IP == nil {
				continue
			}
			value := address.IP.String()
			prefix, bits := address.Netmask.Size()
			if bits != 0 {
				value += fmt.Sprintf("/%d", prefix)
			}
			addresses = append(addresses, value)
		}
		sort.SliceStable(addresses, func(i, j int) bool {
			return !strings.Contains(addresses[i], ":") && strings.Contains(addresses[j], ":")
		})
		if len(addresses) == 0 && device.Name == "windivert" {
			line("    范围  自动覆盖以下网卡，无需逐个选择")
		} else if len(addresses) == 0 {
			line("    地址  未分配 IP 地址")
		}
		for _, address := range addresses {
			line("    地址  %s", address)
		}
	}
	line("\n  ── HTTPS 与目标 ────────────────────────")
	if windows {
		if yes("tls_configured") {
			line("  [已配置] %s", doctorBackend(text("tls_backend")))
		} else {
			line("  [未配置] HTTPS 明文探针")
		}
		if yes("iis_installed") {
			line("  [已发现] 本机 IIS")
		} else {
			line("  [未安装] 本机 IIS（不影响普通 HTTP 采集）")
		}
	} else {
		if yes("ecapture_installed") {
			line("  [已发现] eCapture")
		} else {
			line("  [未发现] eCapture；请检查完整采集包或 --ecapture 路径")
		}
		if yes("btf") {
			line("  [已发现] 内核 BTF · 可继续检查 CO-RE 后端")
		} else {
			line("  [不可用] 内核 BTF · CO-RE 后端无法使用，旧内核可选启动预加载")
		}
	}
	if yes("tls_verified") {
		line("  [已验证] HTTPS 后端（具体覆盖以采集状态为准）")
	} else {
		line("  [待验证] HTTPS 明文能力尚未验证，已配置不代表可采全")
	}
	targets, _ := report["targets"].([]session.Target)
	checks, _ := report["checks"].([]captureCheck)
	if len(targets) == 0 {
		line("  [未发现] 支持的目标服务；这不是自检错误")
		line("           请确认服务已启动，且 --service / --pid 选择正确")
	} else {
		line("\n  已发现 %d 个目标：", len(targets))
		for _, target := range targets {
			line("    %s · PID %d", doctorSafe(target.Service), target.PID)
			line("      标识  %s", doctorSafe(target.ID))
			if target.Library != "" {
				line("      TLS库 %s", doctorSafe(target.Library))
			}
		}
	}
	if len(checks) > 0 {
		line("\n  目标预检：")
		for _, check := range checks {
			status := "不可用"
			if check.Status == "candidate" {
				status = "待附加验证"
			} else if check.Status == "http-only" {
				status = "仅 HTTP（无需探针）"
			} else if check.Status != "unavailable" {
				status = doctorSafe(check.Status)
			}
			line("    [%s] %s · %s", status, doctorSafe(check.Target), doctorBackend(check.Backend))
			line("      %s", doctorSafe(doctorReason(check.Reason)))
		}
	}
	line("\n  ── 下一步 ──────────────────────────────")
	command := "./traffic"
	if windows {
		command = `.\traffic.exe`
	} else if !yes("root") {
		command = "sudo ./traffic"
	}
	line("  验证 HTTP 采集（期间访问本机对应端口的 HTTP 服务）：")
	line("    %s capture --no-tls --ports %s --duration 60s", command, ports)
	line("  中文帮助：%s capture --cn-help", command)
	line("  导出原始自检 JSON：%s doctor --json", command)
	_, err := io.WriteString(w, out.String()+"\n")
	return err
}

// Process names and paths can contain control characters. Keep them from
// introducing terminal escapes or fake report rows.
func doctorSafe(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || r >= 0x80 && r <= 0x9f {
			return ' '
		}
		return r
	}, value)
}

func doctorBackend(value string) string {
	names := map[string]string{"iis-httpapi": "IIS HTTP API", "openssl": "OpenSSL", "ecapture-openssl": "eCapture / OpenSSL", "java-agent": "Java Agent"}
	var result []string
	for _, backend := range strings.Split(value, ",") {
		if name, ok := names[backend]; ok {
			result = append(result, name)
		} else if backend != "" {
			result = append(result, doctorSafe(backend))
		}
	}
	if len(result) == 0 {
		return "未指定后端"
	}
	return strings.Join(result, "、")
}

func doctorReason(value string) string {
	translated := map[string]string{
		"probe is not explicitly enabled": "未配置该目标的明文探针",
		"selected --ports contain no IIS HTTPS bindings; HTTP packet capture covers plain HTTP without Frida": "所选 --ports 未包含 IIS HTTPS 绑定端口；纯 HTTP 由网卡抓包直接还原，无需附加 Frida 探针",
		"probe helper files are not readable":                                                              "探针脚本缺失或不可读",
		"Python executable is unavailable":                                                                 "Python 解释器不可用",
		"probe runtime directory is unavailable":                                                           "探针临时运行目录不可用",
		"cannot import Frida using configured Python":                                                      "配置的 Python 无法导入 Frida",
		"Frida version differs from validated 17.5.1":                                                      "Frida 版本与已验证的 17.5.1 不一致",
		"Frida dependency checked; attach permissions, target ABI and runtime access require verification": "Frida 依赖检查通过；附加权限、目标 ABI 和临时目录访问仍需验证",
		"Java attachment requires explicit opt-in":                                                         "Java 目标需要显式使用 --java-attach",
		"Java agent archive is not readable":                                                               "Java Agent JAR 缺失或不可读",
		"Tomcat NIO only; JVM attach permission and loaded classes require runtime verification":           "仅支持 Tomcat NIO；JVM 附加权限和已加载类仍需验证",
		"eBPF backend requires Linux":                                                                      "eBPF 后端需要 Linux",
		"mapped OpenSSL library is unavailable":                                                            "目标映射的 OpenSSL 库不可用",
		"eCapture executable is unavailable":                                                               "eCapture 可执行文件不可用",
		"CO-RE BTF is unavailable; startup-loaded preload is a separate opt-in":                            "内核 BTF 不可用；可选择在业务启动时加载随包预加载库",
		"current backend requires privileged BPF access":                                                   "当前后端需要特权 BPF 访问权限",
		"library ABI, BPF policy and probe build must be verified at attachment; no coverage guarantee":    "仍需在附加时验证库 ABI、BPF 策略和探针构建，尚不保证覆盖完整",
		"no supported plaintext backend; HTTP packet capture can continue":                                 "当前目标没有可用的明文后端；HTTP 抓包仍可继续",
	}
	if text, ok := translated[value]; ok {
		return text
	}
	return value
}

func writeDoctorOutput(w io.Writer, report map[string]any, ports string, asJSON bool) error {
	if asJSON {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	return writeDoctorReport(w, report, ports)
}
