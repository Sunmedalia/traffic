# 原会话接续摘要

恢复时间：2026-11-17。原会话「梳理仍然欠缺的能力」，ID `01a1e4b6-e188-7973-b06d-eb662e458c05`。
本文件由可读会话记录、当前 Git 状态、OPTIMIZATION.md、VALIDATION.md 交叉整理；用于人工上下文接续，不代表修复加密压缩记录或触发系统压缩。

## 用户目标及约束

- 核心目标：优化采集完整性、环境适配度、降低对目标环境的影响。用户已要求实施完整计划。
- 原会话后续目标：完成优化，再把最新 PR 合进来并解决代码冲突；历史记录指向 PR #4，继续合并前须重新读取远端状态。
- 用户明确要求切回 main 继续；恢复时确实位于 main。
- Linux ARM64、Linux x64、Windows x64 同等验收；保留 CentOS 7、Windows 10 LTSC 17763 支持，纳入 HTTP/2。
- 业务优先：探针不能阻塞业务线程等消费者；资源有界，过载记录缺口。正常动态采集不要求重启服务或更改站点配置；预加载必须显式启用并说明启动加载要求。
- 保留旧会话读取兼容。未知漏采数量、尾部排空和运行时卸载须明确为未知；事件丢失数不能当作请求丢失数。
- 本轮不扩展攻击规则、分析大屏、HTTP/3、WebSocket 内容解析、Go TLS 或通用 JSSE。现有规则的运行开销仍可优化，但须保持检测语义。
- 测试、故障注入和服务回收限于隔离实验环境。原会话曾遭其他工作重置源码，务必保留当前已暂存、未暂存和新增文件。

## 当前工作区

- 路径 `/Volumes/l/traffic`；分支 main；HEAD `f596807`（合并 PR #2）。历史日志还有 `ee3357e`（PR #3）。
- 恢复时有 79 个修改/新增路径，包含混合暂存状态；`git ls-files -u` 为空，当前没有 Git 未解决冲突。这不证明 PR #4 可无冲突合并。
- 优化仍未形成最终提交或完整交付。本次恢复只增加接续材料，不修改业务代码、不提交或合并。
- 关键入口：`OPTIMIZATION.md` 为实施概览及待办；`VALIDATION.md` 顶部为最新 r38/r36/r35 结果，下面保留历史失败，阅读时按版本区分。
- 代码重点：`cmd/traffic/{http.go,tls.go,tls_frames.go,tls_pending.go,services.go,preflight.go,evidence_writer.go,index_writer.go,integrity.go,http2.go,probe_transport.go,probe_sequence.go,kernel_scope.go}`；Java Agent、Windows JS、预加载 C、TUI/Web 和会话模型亦有改动。
- eCapture 源码改动通过 `patches/ecapture-v2.9.1-*.patch` 和 `scripts/build-ecapture.sh` 交付，`scripts/test-ecapture-patches.sh` 验证整套补丁。不可只修改 /tmp 的实验源码而遗漏仓库补丁。

## 已实现与已有验证

- 完整性：独立 gaps.jsonl、按原因/单位计数、连接局部淘汰和配对失效、Content-Length 截断后继续消费、未完成请求保存、目标启动身份及采集代次。
- 生命周期：发现/附加/就绪状态、目标重试、异常终止会话识别；Java/Windows 增加序号和停止状态，完整停止协议尚有缺口。
- 低影响：有界异步原始证据写入、SQLite 有界事务批次/语句复用、PCAP 缓冲、独立 WebSocket 接收、事件身份传递；cgroup v1/v2 资源约束。
- 适配：共用只读 doctor/采集预检、显式网络命名空间选择、HTTP/2 有界帧/HPACK/stream 组装及界面展示。代码支持不等于全后端实机验收。
- eCapture 内核 PID/启动身份/端口过滤、动态撤销、空白名单、损坏配置拒绝及恢复：ARM64 与 Ubuntu x64 原始传输反向验证通过。七组 OpenSSL CO-RE 资产已构建，其他 ABI 运行矩阵未全部通过。
- r35 预加载：固定 128 槽位原子队列、64 个元数据分片、正文复制/编码/传输移出共享锁；三台 Linux 各 20 轮 × 19 条请求，共 1,140 条逐字节核对通过，无已观测缺口。原生并发/容量/fork/传输恢复测试及 x64 TSAN 通过；TSAN 本身不支持的多线程 fork 块只在 sanitizer 下跳过。
- glibc 2.17 目标交叉编译预加载库在 ARM Debian 和 CentOS 7 各通过 19 请求验证；ARM 实机为新 glibc，不能推广至旧 glibc ARM 矩阵。
- 三台 Linux 全仓库 Go 竞态测试及 vet 历史通过；Mac、Java 17/21、Windows CGO 交叉构建等检查有记录，继续修改后按影响范围复验。Mac 本地 Go 链接使用已安装 SDK 14.4，默认 SDK 27 有兼容问题。
- r36：紧凑 Event.Data 按真实长度独立分配、Clone 深复制、编码后 wire 所有权转移。1 KiB 解码基准由约 2.83µs/18,832 B 降至 1.33µs/1,600 B，旧格式及缓冲复用回归通过。
- r38：重排由扫描/重建窗口改为稳定最小堆；约 500 条窗口单次输入基准由 6,221ns/32,081 B 降至 61.5ns/32 B。乱序、相同时间戳、容量和空闲刷新差分回归通过，ARM/x64 定向竞态检查通过。
- `functional-r38`：126 条请求/响应、正文、规则、ZIP 核对通过；仍有 2 个 PCAP 序号缺口及 1 次 eCapture 排空未确认，整体完整性保持 unverified。

## 断点：持续负载仍失败

- 最新 `impact-network-r38`：独立 x64 Go 发流器、64 并发、约 2,526 请求/秒，每种模式 30 秒。baseline 3 个错误、17 个调度丢弃；TLS 9 个调度丢弃，full 81 个调度丢弃。
- TLS/full 各出现 3 次每连接 8 MiB 接收预算耗尽，后端最终 unavailable。P99 约 baseline 6.01ms、TLS 6.54ms、full 7.60ms。此诊断未通过，不能根据单路径基准改善宣称高负载已修好。
- 原会话最后在分析 r39 采集器 CPU/分配 profile，尚未据此提交新的业务代码修复。profile 构建来自远端独立 `profile-src-r39`，并非正式发布构建。
- 两份 CPU profile 合并样本：Frames.ingest 累计约 73%，Store.save 约 60%，detect 约 48%（包含关系，不可相加）；分配约 3.58 GB 为累计 alloc_space，绝非常驻内存峰值。
- 分配热点包括 bufio.NewReaderSize、Frames.feed、JSON 事务恢复；discoverTargets/populateTarget/listeningPorts 合计亦明显。TLS 单份 profile 中持久化/JSON 恢复占比较高。后续应分模式核对，不把 full 模式规则成本泛化为所有模式。
- 最后检查 `services.go`：目标发现每次为各目标读取网络表和 FD；检查 `preflight.go` 的重复预检/能力 manifest。以上为诊断线索，尚未证实具体修复或性能收益。

## 必须继续完成

1. 利用 r39 profile 定位并修复持续处理能力不足，复核采集器/子进程 cgroup 预算、解析、恢复/持久化和目标发现成本；不能靠持续扩大缓冲宣称解决吞吐问题。
2. eCapture 最终计数/端到端排空握手、预加载显式停产与最终丢失确认；统一默认 5 秒排空、15 秒解除附加、30 秒总停止预算。当前部分后端仍 unverified。
3. OpenSSL 1.1.1 配套探针、glibc/架构兼容产物包及运行验证。预检包含 1.1.1 capability manifest 检查不等于产物已验收。
4. Windows LTSC/Server 2022、HTTP/2 各后端、容器 TLS/进程发现及完整故障矩阵，含慢盘/满盘/SQLite 故障、worker 更替、应用池回收、fork、强制退出。
5. 正式低影响和 8 小时长压、各后端 20 次启停、残留/清理检查。已有预加载 20 轮不能替代其他后端。
6. 文档与证据对齐、整理提交；完成优化后重新读取最新 PR（历史为 #4），解决冲突、验证并合入。

## 正式验收门槛

- 独立实测基线容量的 30%/60%/80%；baseline、packets、tls、full 四种模式，每组 15 分钟、重复 3 轮；8 小时检查资源趋势。
- 吞吐下降 ≤3%；P99 增量 ≤max(基线 P99×5%, 1ms)；目标 CPU 增量 ≤单核 5%；目标额外私有内存 ≤32 MiB；错误数不增加。
- 发流器过载或采样缺失不能通过。逐请求账本核对漏采、重复、错配、正文；无故障且后端就绪后的支持场景要求三者为零。
- 启动盲区单列；饱和允许有界丢失，但必须报告已知缺口、不串流、不死锁。零观测丢失不等于全部采全。
- drain confirmed、hook 恢复、脚本卸载、transport detach、运行时驻留分别报告；预加载库及 Java 类驻留边界必须保留。

## 环境、证据和接续入口

- 用户授权测试机：192.168.1.7 Debian ARM64；192.168.1.10 Ubuntu x64；192.168.1.12 CentOS 7 x64。登录信息在原用户消息中，本摘要不重复保存密码。
- 三台远端隔离根目录 `/opt/traffic-lab-20261117-7481e4c3`，源码在其 `src`，探针实验版本如 `ecapture-r38`、`bin/ecapture-r38`。服务 PID 必须重新发现，不复用旧脚本中的硬编码 PID。
- 本地证据 `validation/optimization-20261117/` 为 Git 忽略目录；预加载汇总 `preload-r35-summary.json`。原始请求/正文/PCAP 不应随源码提交。
- 本地控制工具 `/tmp/traffic-lab-control/remote.py`，Python 环境 `/tmp/traffic-lab-tools/bin/python`；使用前确认仍存在。授权仅覆盖上述实验范围。
- 最新诊断：`/tmp/traffic-lab-control/functional-r38.log`、`impact-network-r38.log`、`profile-collector-r39.log`、`profile_collector_r39.py`、`collector-r39-3809151.{cpu,allocs}`、`collector-r39-3834590.{cpu,allocs}`。
- eCapture 补丁实验源码 `/tmp/traffic-ecapture-optimization-source`；干净补丁验证 checkout `/tmp/traffic-ecapture-apply-r36`。临时目录与远端产物需先检查，旧 PTY/session ID 不能视为仍在运行。
- 原始会话 `/Users/liuxunzhang/.codex/sessions/2026/11/16/rollout-2026-11-16T22-15-53-01a1e4b6-e188-7973-b06d-eb662e458c05.jsonl`。保留原文件；不手工改写 encrypted_content 或导入失败 cmp 项。
- 原计划另保存于 `validation/session-recovery-20261117/ORIGINAL_PLAN.md`；恢复时 Git 状态保存于同目录。继续时先读本摘要、OPTIMIZATION.md、VALIDATION.md 顶部，再核对实际文件和进程。

本次继承完成的是文本摘要与证据索引。系统会话压缩、原加密项修复、优化交付、PR 合并均不能因此标记完成。
