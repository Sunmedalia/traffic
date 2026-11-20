package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

func consoleHelpFlag(args []string, name string) bool {
	for _, arg := range args {
		if arg == "--"+name || arg == "-"+name {
			return true
		}
	}
	return false
}

func consoleHelpOptions(cmd string) map[string]bool {
	names := "session json"
	switch cmd {
	case "view":
		names = "session data-dir rules-dir refresh client rule severity since service"
	case "web":
		names = "session data-dir rules-dir listen allow-remote refresh"
	case "analyze":
		names = "session rules scan-window scan-paths alert-webhook request-limit response-limit json"
	case "requests", "events":
		names = "session limit service client rule severity since json"
	case "export":
		names = "session out"
	}
	result := map[string]bool{}
	for _, name := range strings.Fields(names) {
		result[name] = true
	}
	return result
}

func printConsoleHelp(w io.Writer, cmd string, cn bool, fs *flag.FlagSet) {
	if cmd == "" {
		if cn {
			fmt.Fprintln(w, `traffic-console — 本地流量分析与取证

用法：traffic-console <命令> [参数]
  view       中文终端会话浏览（默认命令）
  web        浏览器分析、规则文件管理与后台分析
  analyze    停采后还原、配对、索引并执行规则匹配
  rules      校验自定义 YAML 规则：rules check FILE
  status     查看采集状态及已有分析信息
  requests   查询请求（JSON）
  events     查询告警（JSON）
  show ID    查看请求、响应及检测依据
  export ID  导出证据 ZIP

traffic 只保存原始流量；console 在本地完成还原、配对、索引和规则匹配。
Web 顶部「规则与分析」支持新建、导入、编辑、校验、下载及删除规则文件。

示例：
  traffic-console web --data-dir ./sessions --rules-dir ./rules
  traffic-console analyze --session ./sessions/case --rules ./rules/custom.yaml
  traffic-console --session ./sessions/case
  traffic-console rules check ./rules/custom.yaml

帮助：traffic-console web --cn-help / analyze --cn-help / rules --cn-help
--help 显示英文帮助；--cn-help 显示中文帮助。`)
		} else {
			fmt.Fprintln(w, `traffic-console — local traffic analysis and evidence

Usage: traffic-console <command> [options]
  view        Browse sessions in the terminal (default)
  web         Browse evidence, manage YAML rules and run local analysis
  analyze     Reconstruct, pair, index and match a stopped session
  rules       Validate custom rules: rules check FILE
  status      Show capture status and saved analysis metadata
  requests    Query requests as JSON
  events      Query alerts as JSON
  show ID     Show request, response and alert details
  export ID   Export an evidence ZIP

Examples:
  traffic-console web --data-dir ./sessions --rules-dir ./rules
  traffic-console analyze --session ./sessions/case --rules ./rules/custom.yaml
  traffic-console --session ./sessions/case
  traffic-console rules check ./rules/custom.yaml

Collection saves raw traffic. Local analysis reconstructs TCP/HTTP, pairs messages, indexes and matches rules.
Use traffic-console <command> --help for command-specific help.
中文帮助：traffic-console --cn-help / web --cn-help / analyze --cn-help`)
		}
		return
	}
	usage := "traffic-console " + cmd + " [options]"
	if cmd == "rules" {
		usage = "traffic-console rules check FILE.yaml"
	}
	if cmd == "show" || cmd == "export" {
		usage = "traffic-console " + cmd + " ID --session DIR [options]"
	}
	if cn {
		fmt.Fprintln(w, "用法："+usage+"\n\n参数：")
	} else {
		fmt.Fprintln(w, "Usage: "+usage+"\n\nOptions:")
	}
	translations := map[string]string{
		"session": "已有会话目录（原始采集数据保持只读）", "data-dir": "会话搜索根目录，默认程序旁的 sessions",
		"rules-dir": "Web 与 TUI 分析面板使用的规则目录，默认程序旁的 rules；源码 bin 构建使用项目根目录",
		"rules":     "追加 YAML 规则文件；不指定时仅使用内置规则", "scan-window": "扫描行为关联窗口，默认 1m", "scan-paths": "扫描行为不同路径阈值，默认 20",
		"request-limit":  "本地还原及检测的请求正文上限，默认 1 MiB，最大 16 MiB",
		"response-limit": "本地还原及检测的响应正文上限，默认 1 MiB，最大 16 MiB",
		"alert-webhook":  "本地分析成功后投递告警；令牌从 TRAFFIC_WEBHOOK_TOKEN 读取",
		"listen":         "Web 监听地址，默认 127.0.0.1:8080", "allow-remote": "允许非回环地址上的明文 HTTP 访问", "refresh": "界面刷新间隔，默认 1s；Web 最小 500ms",
		"out": "证据 ZIP 路径，不覆盖已有文件", "limit": "最多返回的查询结果数，默认 100", "service": "按服务筛选", "client": "按来源 IP 或 IP:端口筛选",
		"rule": "按规则 ID 筛选", "severity": "最低告警级别：low / medium / high", "since": "RFC3339 起始时间", "json": "查询默认输出 JSON",
	}
	if fs != nil {
		allowed := consoleHelpOptions(cmd)
		fs.VisitAll(func(f *flag.Flag) {
			if !allowed[f.Name] {
				return
			}
			description := f.Usage
			if cn && translations[f.Name] != "" {
				description = translations[f.Name]
			}
			fmt.Fprintf(w, "  --%-20s %s", f.Name, description)
			if !cn && f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" {
				fmt.Fprintf(w, " (default %q)", f.DefValue)
			}
			fmt.Fprintln(w)
		})
	}
	if cn {
		fmt.Fprintln(w, "\n使用示例：")
	} else {
		fmt.Fprintln(w, "\nExamples:")
	}
	examples := map[string][]string{
		"view":     {"traffic-console --session ./sessions/case", "traffic-console --data-dir ./sessions"},
		"web":      {"traffic-console web --data-dir ./sessions --rules-dir ./rules", "traffic-console web --session ./sessions/case --listen 127.0.0.1:8080"},
		"analyze":  {"traffic-console analyze --session ./sessions/case", "traffic-console analyze --session ./sessions/case --rules ./rules/custom.yaml --scan-window 1m --scan-paths 20"},
		"rules":    {"traffic-console rules check ./rules/custom.yaml"},
		"status":   {"traffic-console status --session ./sessions/case"},
		"requests": {"traffic-console requests --session ./sessions/case --limit 100"},
		"events":   {"traffic-console events --session ./sessions/case --severity medium"},
		"show":     {"traffic-console show REQUEST_ID --session ./sessions/case"},
		"export":   {"traffic-console export REQUEST_ID --session ./sessions/case --out ./evidence.zip"},
	}
	for _, example := range examples[cmd] {
		fmt.Fprintln(w, "  "+example)
	}
	if cmd == "web" {
		if cn {
			fmt.Fprintln(w, "\n打开启动时输出的令牌地址，在顶部「规则与分析」管理文件并选择会话执行分析。\n规则目录自动创建；单文件最多 1 MiB、最多 256 个文件。内置规则只读。\n保存前校验，版本冲突时需重新打开；规则变更后需重新分析。\nWeb 分析不发送 Webhook；原始采集数据保持只读。")
		} else {
			fmt.Fprintln(w, "\nOpen the printed token URL. Use Rules and analysis to manage files and analyze a session.\nThe rules directory is created automatically. Limit: 1 MiB/file, 256 files; built-in rules are read-only.\nSaving validates rules and checks file revisions. Analyze again after changing rules.\nWeb analysis does not send webhooks. Original capture evidence stays read-only.")
		}
	}
	if cmd == "analyze" {
		if cn {
			fmt.Fprintln(w, "\n先停止采集，再把完整会话复制到本地分析。原始会话先还原再匹配；结果写入 analysis-*.sqlite，由 analysis-current.json 原子选择。\n失败或取消保留上次结果；请求/响应正文默认各 1 MiB，可调至 16 MiB 后重跑。\n原始流量保持只读；缺失的原始流量无法恢复。")
		} else {
			fmt.Fprintln(w, "\nStop capture first and copy the complete session locally. Raw sessions are reconstructed before matching. Results go to analysis-*.sqlite, selected atomically by analysis-current.json.\nFailure or cancellation keeps the last result. Body limits default to 1 MiB each, maximum 16 MiB; raise them and rerun.\nOriginal evidence stays read-only. Missing raw traffic cannot be recovered.")
		}
	}
	if !cn {
		fmt.Fprintln(w, "\n中文帮助：traffic-console "+cmd+" --cn-help")
	}
}
