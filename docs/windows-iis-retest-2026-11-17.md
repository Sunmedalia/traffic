# 2026-11-17 Windows IIS 启动前十条请求专项复测

> 以下是修复前的失败基线，保留追溯。后续源码修复与最终验收见 [IIS 修复报告](windows-iis-fix-2026-11-17.md)。

## 结论

**启动完整性验收失败，前十条 HTTPS 请求遗漏仍稳定复现。** 探针报告 `attached` 后立即发流，不发送任何附加后预热请求。13 轮 HTTPS 专项中，前十条共 130 条，全部没有进入最终请求索引。快速复用已有 HTTPS 连接时，另有两条在前十条之外遗漏；其原始探针请求事件也不存在，不能归因于离线分析。

明文 HTTP 使用 Npcap 的两轮前十条测试则全部通过。常规 IIS 矩阵在明确预热后通过，不代表启动窗口通过。

## 环境和构建

- 主机：192.168.1.11，Windows 10 企业版 LTSC x64，版本 10.0.17763，IIS 10。
- 站点：已有 `TrafficLab`，HTTP 8080、HTTPS 8443；HTTP/1.1、TLS 1.2。
- Python 3.14.2、Frida 17.5.1，使用已安装的 Npcap 回环接口。本轮没有验证完整 Windows 便携包的 WinDivert 后端。
- 采集器、console 和两组原生测试程序来自 `c2ee58b8474f416c36bc3caf81eeb228594e7779` 的产品源码，以 Go 1.26.11、CGO 和 x64 MinGW 交叉构建。IIS Python/JavaScript 探针也取自当前源码；本轮没有修改采集器或探针。
- Windows 原生 `cmd/traffic`、`cmd/traffic-console` 测试均通过，Windows 目标 `go vet ./...` 通过。

## 不预热专项

每轮先在采集前访问站点，确保 IIS 工作进程已运行，并准备一条已有 HTTPS 连接；随后启动采集，轮询到 `tls=attached` 后立即发送带唯一编号的请求。采集前访问不计入下表，附加后不发送未记账的预热请求。

请求均为带唯一正文的 `/api/echo` POST；客户端逐条检查状态 200 和回显正文，再与离线还原结果核对唯一性、后端、请求/响应正文、完整性和截断状态。

| 场景 | 轮数 × 每轮条数 | 前十条采到 / 发出 | 全部采到 / 发出 |
| --- | --- | --- | --- |
| HTTPS，每次新建连接，连续发流 | 5 × 30 | 0 / 50 | 100 / 150 |
| HTTPS，复用附加前已有连接，连续发流 | 3 × 30 | 0 / 30 | 58 / 90 |
| HTTPS，新连接且仅发送十条 | 2 × 10 | 0 / 20 | 0 / 20 |
| HTTPS，已有连接，每条间隔 50 ms | 3 × 30 | 0 / 30 | 60 / 90 |
| HTTP，每次新建连接，仅发送十条 | 2 × 10 | 20 / 20 | 20 / 20 |

HTTPS 共 350 条，采到 218 条；前十条的 130 条全部遗漏，另外两条分别是快速已有连接第 2 轮的第 21 条、第 3 轮的第 19 条。原始事件文件未出现对应请求 URL。已还原的 218 条 HTTPS 和 20 条 HTTP 均通过正文及配对检查。

50 ms 间隔的三轮未出现额外缺失，只是该样本的观测结果，不能证明低速流量一定采全；本轮未进一步定位额外两条的确切触发机制。

## 常规矩阵与脚本问题

保留原有 24 条显式预热，其中仅采到 14 条；再执行 107 条常规矩阵，最终通过 HTTP/HTTPS、已有连接、中文、分块、大正文、并发、状态码、五类规则及证据 ZIP 校验。该结果与上述启动失败分开报告。

重跑时发现 `scripts/windows/verify-iis.py` 使用系统默认 GBK 读取 UTF-8 状态 JSON，发生 `UnicodeDecodeError`，导致前两次常规矩阵未完成。本轮将状态和分析指针的三处读取改为显式 UTF-8，修正脚本后完整矩阵通过。失败会话及日志保留；这不是启动漏采问题的修复。

## 完整性及生命周期

- 所有专项会话的 `tls_dropped`、`queue_dropped`、`dropped` 均为零，但已通过客户端账本证实遗漏。零计数不能作为采全依据。
- 只发送十条 HTTPS 的两轮中，`plaintext_observed=false`、`probe_receive_matches=0`，默认采集仍以 0 退出；`attach_window_suspect=false` 也不能排除启动盲区。状态保留了通用启动遗漏提示及 `tls_coverage=unverified`。
- 专项会话报告 `data_drained=true`、`hooks_removed=true`，但 `script_unloaded=false`、`transport_detached=false`；有序排空仅能覆盖探针已产生的事件，不能补回未观测的接收。Frida 运行时仍可能驻留。
- 前十条现象与源码说明的附加前已投递 `HttpReceiveHttpRequest` 无法补抓相符。十条是这台机器本次默认应用池的实测值，不是通用固定上限，也不能把发十条预热当成完整性保证。

本轮没有回收应用池或重启 IIS。测试前后工作进程身份保持 `7452:134393939778926138`，站点配置、处理器源码、静态文件及 `applicationHost.config` 哈希不变。最终健康检查返回 200，没有本轮采集器或辅助测试进程残留；这不表示目标内 Frida 运行时已卸载。

## 证据

远端隔离目录：`C:\traffic-iis-retest-20261117`。本地 Git 忽略目录：`validation/windows-iis-retest-20261117/`。

逐轮账本、就绪状态快照、原始 PCAP/TLS API 事件、分析库、缺口记录、helper 日志和证据 ZIP 保留于 `artifacts.zip`；不打包可执行文件及探针运行时 DLL 副本。汇总文件为各 `startup-*/summary.json`，常规矩阵为 `full-matrix-r3/verification.json`。构建来源及本地二进制哈希见 `build-provenance.json`，远端二进制哈希、站点最终健康和清理结果见 `final-report.json`。

本地再次核对：132 条遗漏 HTTPS 请求在各自原始请求事件中均不存在，15 个导出 ZIP 的 SHA-256 清单全部通过，远端四个可执行文件与本地构建哈希一致。归档收据见 `verification-receipt.json`。

本轮是测试和问题复现，不代表 IIS 启动完整性已修复；未执行 TLS 1.3、HTTP/2、应用池回收、长期压力或完整运行时卸载验收。
