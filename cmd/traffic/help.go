package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

var doctorHelpFlags = map[string]bool{}

func init() {
	for _, name := range strings.Fields("interfaces ports service pid libssl ecapture netns-pid java-attach java-pid java-agent java-helper iis-probe iis-python iis-runtime-dir probe-python probe-runtime-dir openssl-probe openssl-profile json") {
		doctorHelpFlags[name] = true
	}
}
func helpRequest(args []string) (string, bool, bool) {
	command := ""
	requested, cn := false, false
	for index, arg := range args {
		if index == 0 && arg == "help" {
			requested = true
			continue
		}
		switch arg {
		case "--cn-help", "-cn-help":
			requested, cn = true, true
		case "--help", "-help", "-h":
			requested = true
		case "doctor", "capture", "import":
			if command == "" {
				command = arg
			}
		}
	}
	return command, cn, requested
}
func printCollectorHelp(w io.Writer, cmd string, cn bool, fs *flag.FlagSet) {
	if cmd == "" {
		if cn {
			fmt.Fprintln(w, `traffic — 网站流量采集与取证

用法：traffic <命令> [参数]
  doctor    检查接口、权限、随包依赖和 HTTPS 后端；不开始采集
  capture   保存原始网络包及探针明文；本地 console 负责还原与分析
  import    将已有 PCAP 保存为原始会话

示例：
  traffic doctor
  traffic capture --ports 80,443 --duration 60s
  traffic capture --no-tls --ports 8080
  traffic import capture.pcap --ports 80,8080
  traffic-console analyze --session sessions/某个会话
  traffic-console --session sessions/某个会话

子命令帮助：
  traffic doctor --cn-help
  traffic capture --cn-help
  traffic help capture --cn-help
  --help 显示英文帮助；--cn-help 显示中文帮助。

发行包依赖自动从程序旁查找，不依赖当前工作目录。
Windows 采集请使用管理员终端；Linux 采集通常需要 root。
HTTPS 覆盖取决于后端、目标 ABI 和附加窗口，零丢弃不代表采全。`)
		} else {
			fmt.Fprintln(w, `traffic — website traffic capture and evidence

Usage: traffic <command> [options]
  doctor   Inspect interfaces, privileges, dependencies and TLS backends
  capture  Save raw network packets and TLS probe events
  import   Save an existing PCAP as a raw session

Examples:
  traffic doctor
  traffic capture --ports 80,443 --duration 60s
  traffic capture --no-tls --ports 8080
  traffic import capture.pcap --ports 80,8080
  traffic-console analyze --session SESSION
  traffic-console --session SESSION

Use traffic <command> --help for command-specific help.
中文帮助：traffic --cn-help / traffic capture --cn-help`)
		}
		return
	}
	title := map[string]string{"doctor": "环境自检（只读，不开始采集）", "capture": "开始流量采集", "import": "导入 PCAP"}[cmd]
	if cn {
		fmt.Fprintf(w, "traffic %s — %s\n\n", cmd, title)
	} else {
		fmt.Fprintf(w, "traffic %s\n\n", cmd)
	}
	usage := "traffic " + cmd + " [options]"
	if cmd == "import" {
		usage = "traffic import FILE.pcap [options]"
	}
	if cn {
		fmt.Fprintln(w, "用法："+usage+"\n\n常用参数：")
	} else {
		fmt.Fprintln(w, "Usage: "+usage+"\n\nOptions:")
	}
	descriptions := map[string]string{
		"interfaces": "接口列表，逗号分隔；Windows 随包 WinDivert 默认覆盖本机接口和回环", "ports": "业务 TCP 端口，默认 80,443", "service": "目标服务：auto/nginx/apache/tomcat/openssl/iis", "pid": "只检查或采集指定进程", "libssl": "覆盖 OpenSSL 动态库路径或模块名", "ecapture": "eCapture 路径，默认使用随包版本", "netns-pid": "Linux 目标网络命名空间 PID", "java-attach": "显式附加 Java Agent（Tomcat NIO）", "java-pid": "Java 目标 PID", "java-agent": "Java Agent 文件，默认查找随包 JAR", "java-helper": "带 jdk.attach 的 Java 可执行文件", "json": "输出 JSON（doctor 默认显示中文自检报告）", "duration": "采集时长，例如 60s、10m；0 表示直到 Ctrl+C", "output": "精确的会话输出目录，必须为新目录", "data-dir": "会话根目录，默认位于程序旁的 sessions", "name": "会话名称", "no-tls": "仅抓网络包，不附加明文探针", "no-detect": "兼容旧参数；采集始终不执行检测", "trusted-proxies": "可信代理 IP/CIDR，逗号分隔", "require-plaintext": "IIS 未记录请求侧明文时非零退出；仅检查原始事件，不做 HTTP 还原", "require-tls": "HTTPS 预检失败时拒绝开始", "collector-memory-mib": "采集器及子进程内存预算 MiB，默认 256", "collector-cpu-percent": "单核 CPU 百分比预算，默认 50", "drain-timeout": "探针数据排空等待，默认 5s", "stop-timeout": "停止后的总等待预算，默认 30s，不小于 --drain-timeout；超时记录缺口并标记排空未确认", "disk-limit-mib": "会话磁盘预算 MiB，默认 2048", "openssl-preload-socket": "Linux 预加载明文 socket；必须先在服务启动时加载库", "openssl-preload-allow-uid": "允许预加载事件的非 root UID", "iis-probe": "覆盖随包 IIS 探针脚本", "openssl-probe": "覆盖随包 OpenSSL 探针脚本", "iis-python": "覆盖随包 Python 解释器", "probe-python": "覆盖随包 Python 解释器", "iis-runtime-dir": "覆盖自动创建的 Frida 运行目录", "probe-runtime-dir": "覆盖自动创建的 Frida 运行目录", "openssl-profile": "覆盖静态 OpenSSL 二进制 profile"}
	if fs != nil {
		fs.VisitAll(func(f *flag.Flag) {
			if cmd == "doctor" && !doctorHelpFlags[f.Name] {
				return
			}
			if cmd == "import" && (doctorHelpFlags[f.Name] && f.Name != "ports" && f.Name != "json") {
				return
			}
			text := f.Usage
			if cn {
				if translated := descriptions[f.Name]; translated != "" {
					text = translated
				}
			}
			fmt.Fprintf(w, "  --%-25s %s\n", f.Name, text)
		})
	}
	examples := map[string][]string{
		"doctor":  {"traffic doctor", "traffic doctor --json", "traffic doctor --service nginx --ports 443", "traffic doctor --service openssl --pid 1234"},
		"capture": {"traffic capture --ports 80,443 --duration 60s", "traffic capture --no-tls --ports 8080 --output sessions/http-case", "traffic capture --service openssl --pid 1234 --ports 9443", "traffic capture --service iis --ports 80,443 --duration 10m", "traffic capture --java-attach --pid 1234 --ports 8443"},
		"import":  {"traffic import capture.pcap --ports 80,8080 --output sessions/imported"},
	}
	if cn {
		fmt.Fprintln(w, "\n使用示例：")
	} else {
		fmt.Fprintln(w, "\nExamples:")
	}
	for _, example := range examples[cmd] {
		fmt.Fprintln(w, "  "+example)
	}
	if cmd == "capture" || cmd == "import" {
		if cn {
			fmt.Fprintln(w, "\n采集和导入只保存原始流量，不做 TCP/HTTP 还原、配对、索引或规则匹配。\nPCAP 分段顺序保留，达到磁盘预算停止；正文分析上限在 console 中设置。\n停采后在本地运行：\n  traffic-console analyze --session SESSION [--rules FILE]\n  traffic-console web --session SESSION --rules-dir ./rules\n规则校验：traffic-console rules check FILE。")
		} else {
			fmt.Fprintln(w, "\nCapture and import save raw traffic without TCP/HTTP reconstruction, pairing, indexing or matching.\nPCAP segments are retained until the disk budget stops capture. Set body limits in console. After capture stops, run locally:\n  traffic-console analyze --session SESSION [--rules FILE]\n  traffic-console web --session SESSION --rules-dir ./rules\nValidate rules: traffic-console rules check FILE.")
		}
	}
	if cn && cmd == "capture" {
		fmt.Fprintln(w, "\nWindows：在管理员 PowerShell 中执行 .\\traffic.exe capture ...。\nUbuntu/CentOS：使用 sudo ./traffic capture ...。\nCtrl+C 停止并保存会话；用 traffic-console 打开会话。\n旧内核预加载需要目标进程在启动时加载随包库，工具不会自动重启业务服务。")
	}
	if !cn {
		fmt.Fprintln(w, "\n中文帮助：traffic "+cmd+" --cn-help")
	}
}
