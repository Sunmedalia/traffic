# 验证记录

## 2026-11-17 Windows IIS 请求遗漏修复：最终实机通过

完成上下文和正文/响应 API 按请求 ID 恢复预投递接收，增加去重；HTTP API 改用自身返回回调，修复手工返回帧配对造成的正文和结束标记缺失。最终在 .11 的 IIS 10 / LTSC 17763 上，零预热 20 轮 560 条 HTTPS 请求全部通过，前十条共 200/200；另有零预热 107 条常规矩阵通过。前十条包含分块、大正文和文件响应，四路并发逐字节核对通过。

最终验收阶段进程身份及配置不变、健康 200、测试进程无残留。但早期候选曾引起测试 w3wp 的 Frida 崩溃，该候选已撤除，不能声称整个修复过程无业务影响。完整实现、失败记录、最终验收及证据见 [IIS 修复报告](docs/windows-iis-fix-2026-11-17.md)。覆盖仍为 unverified，运行时完整卸载及长期性能尚未证明。

## 2026-11-17 Windows IIS 前十条专项复测：未通过

192.168.1.11（Windows 10 LTSC 17763 / IIS 10）使用当前产品源码重新构建。13 轮不预热 HTTPS 专项中，附加就绪后每轮前十条共 130 条全部遗漏；快速已有连接还额外遗漏第 21 / 19 条，原始探针中也没有对应请求事件。HTTPS 共采到 218/350，已采到的正文及配对均通过。HTTP 前十条两轮 20/20 通过。丢弃计数均为零，不能据此判断采全。

Windows 采集器和 console 原生测试、目标 vet 通过；修复验收脚本默认 GBK 读取 UTF-8 JSON 的问题后，带 24 条预热的 107 条常规矩阵通过。脚本修正不解决探针启动遗漏。详细逐轮结果、生命周期限制及证据见 [Windows IIS 专项复测](docs/windows-iis-retest-2026-11-17.md)。

## 2026-11-17 当前源码三台 Linux 实机复测

固定 `c2ee58b` 源码快照，在 Debian 13 ARM64（192.168.1.7）、Ubuntu 26.04 x64（192.168.1.10）、CentOS 7 x64（192.168.1.12）原生构建，全仓库竞态测试及 vet 通过。Debian/Ubuntu 各 126 条 HTTP/TLS 请求响应、正文、五类规则及证据导出核对通过；三台各 19 条预加载用例、网络命名空间采集、PCAP 导入分析和实际 Web HTTP API 验证通过。测试进程无残留。

两台 eCapture 功能会话各有一次停止排空未确认，预加载端到端排空同样未确认；覆盖及排空仍为 `unverified`。未执行 HTTP/2 实机、全后端矩阵、持续高负载或长压。详细环境、临时目录低磁盘首轮失败及复验、测试范围和证据入口见 [三台 Linux 复测报告](docs/linux-retest-2026-11-17.md)。

## 2026-11-17 边界修复与原始采集迁移（当前源码，未发布）

采集器已移除还原、配对和 SQLite 索引，本地 console 接管处理；修复分析路径符号链接、重算后元数据混用、导入错误漏报、导入磁盘预算和取消接口阻塞五项问题。全量竞态测试、静态检查、Python 九项回归、本机构建及 Windows x64 交叉构建通过；独立 PCAP CLI 链路和磁盘预算失败路径通过。详细证据与未验收范围见 [本轮边界审核](docs/boundary-review-2026-11-17.md)。历史记录仍对应当时架构，本轮没有执行远端 TLS 全后端及长压验收。

## 2026-11-17 Web 规则文件管理（当前源码，未发布）

- Web 增加独立规则目录，默认程序旁 `rules/`，可用 `--rules-dir` 指定。新增规则文件列表、读取、校验、保存和删除接口，全部沿用 Bearer 令牌验证；限制文件名、1 MiB 大小和 256 文件数量，拒绝符号链接，修改/删除时核对内容版本。
- 页面支持新建、导入 UTF-8 YAML、编辑、校验、保存、下载和删除；内置规则只读。可选择会话及规则执行后台分析、查询状态和取消，任务使用独立规则/扫描状态；完成后重新打开 Web 读取连接，刷新告警与详情。
- 全仓库 Go 竞态测试、go vet、JavaScript 语法及差异空白检查通过，Windows x64 分析器 CGO 交叉构建通过。接口回归覆盖无效规则、正则及重复 ID、版本冲突、文件权限、目录/符号链接边界、分析及缓存刷新。
- 本地 Chrome 实际验证新建并保存 `custom.yaml`、选择该文件分析离线 PCAP 会话：1 条事务产生 3 条告警（含自定义规则），后台完成状态、告警数及概览自动更新，原始采集库保持只读。390×844 视口下规则面板无横向溢出。实测修复了分析按钮遗漏点击绑定的问题。
- 本轮未执行远端 TLS 服务或高负载验收，没有发布新版本。

## 2026-11-17 采集与本地规则分析分离（当前源码，未发布）

- 规则、URL 解码匹配、gzip 检测、扫描行为及告警 Webhook 移至 traffic-console；capture/import 只保存流量。旧会话告警仍可读取，analyze 会用本次规则重新计算。
- 新增回归覆盖疑似攻击请求/响应在采集库不产生告警、离线规则及扫描检测、TUI/Web 查询、本地重算、旧告警替换、只读原始索引、写入失败/取消回滚、活动采集拒绝分析、索引变化后结果失效，以及导出中的原始记录与分析来源。
- 本机 Go 全仓库竞态测试、go vet、Python 九项回归和修改脚本语法检查通过；Windows x64 采集器/分析器 CGO 交叉构建通过。macOS 使用 SDK 14.4，链接有部署版本警告。
- 独立 CLI 验证：生成含 SQLi 请求及 passwd 特征响应的 PCAP，traffic import 保存一条事务且无告警；traffic-console analyze 检出两条告警，events/show/export 读取正常，证据 ZIP 全部 SHA-256 校验通过，原始 index.sqlite 哈希未变化。
- 未执行本轮远端 Linux/Windows TLS 实机、持续高负载或长压；不以检测迁移推导性能收益。v0.1.2 发行包仍是旧检测流程。

## 2026-11-17 下一轮消费链路 r40/r41

交接时 `4b6718c` 的全部 CI 已通过。无其他编译任务时再次测基线，1,000 请求/秒连续两轮各六十秒、各 60,000 条请求均无错误和调度丢弃；随后按用户切换任务的要求停止第三轮及后续测试。此次记录只有两轮，未形成计划要求的三轮容量证明，也不是新版持续采集的验收结果。控制进程正常终止信号退出（143），已确认两台机器没有遗留本轮发流或采集进程。

r40 在三台 Linux（ARM64 Debian、Ubuntu x64、CentOS 7）通过全仓库竞态测试、vet 和构建；ARM64 的 126 条请求/响应、正文、五类规则、站点配置/进程身份及证据 ZIP 复验通过。仍有历史 PCAP 序号缺口与排空未确认，不能据此宣称整体完整性已验证。r41 增加规则必要条件预筛选后，三台 Linux 再次通过全仓库竞态测试、vet 和构建；ARM64 126 条功能、正文、规则及导出核对也通过。

本地同一 1 KiB 请求/响应配对基准各三次：完整 TLS frame 中位数由约 56.0µs/42.6 KiB/195 次分配降至 46.4µs/37.1 KiB/179 次；streaming 约 61.0µs/106.5 KiB/196 次降至 46.8µs/37.2 KiB/180 次。该基准关闭规则检测，不含完整探针链路。

从本轮修改前的 main（66183be）提取同一检测基准作对照：1 KiB 普通文本中位数约 227.7µs 降至 16.2µs，含两轮百分号编码的 990 字节样本约 559.1µs 降至 40.2µs。此为两个固定正常样本的单路径结果，不能推导攻击输入、Unicode 或整体吞吐改善倍数。预筛选与禁用预筛选的原正则执行逐条差分；最新三十秒模糊测试约 40,216 次执行通过，覆盖大小写折叠、未知/可选分支及已有规则。

独立 x64 发流向 ARM64 的容量重测在 1,000 请求/秒第一轮六十秒无错误/无调度丢弃，第二轮出现 83 个发生器调度丢弃；因此未形成有效基线容量，没有启动正式性能验收，不能沿用早期回环 8,420 请求/秒当作新基准。原始记录在 Git 忽略目录 `validation/optimization-next/`，远端隔离源码/产物在 `/opt/traffic-lab-20261117-7481e4c3/next-20261117/`；r41 使用其 `r41` 子目录，后续负载仍待验证。

## 2026-11-17 提交及 PR #4 合并检查

提交优化快照前，本机 Go 全仓库竞态测试及 vet、Java 17/21 Maven verify、Windows x64 CGO 交叉构建、Python 六项回归及 Shell/JavaScript 语法检查通过。Go 使用已安装的 macOS SDK 14.4；Java 显式选择 ARM64 JDK，避免当前默认 x86_64 Java 8 无法运行。

PR #4 与当前 main 冲突处理保留新 TUI 框架、告警聚合和最低级别筛选，同时保留已有 Web 界面、采集诊断及导出字段。完整性、排空和退出状态移至健康页，HTTP/2 协议、stream ID 和完整性原因保留在详情。新增合并回归验证诊断可见性、异常终止告警，以及 TUI 包含截止时刻、Web 不包含截止时刻的既有筛选边界。合并后的全仓库 Go 竞态测试及 vet 通过。这些检查不代表剩余高负载或实机验收通过。

## 2026-11-17 优化版本 Linux 复验进度

### r38 时间戳重排开销

r37 对 r36 探针采集了两个五秒 CPU profile，覆盖运行期而非仅启动：合计样本中 `flushByLag` 约占 12.8%，后台 GC 约占 23.2%。旧实现每次输入扫描窗口，刷新时重新分配/复制保留队列。替换为 typed min-heap，并以到达序号保持相同时间戳的稳定顺序；待排上限、延迟及容量压力刷新规则未改变。

ARM64 固定 100ms 延迟、每 200µs 一条事件（约 500 条窗口）的基准各测三次，中位数从约 6,221ns/32,081 B/op 降至 61.5ns/32 B/op。随机差分测试覆盖 4 种延迟、5 种容量、每种 4,096 个乱序/相同时间戳事件，并穿插空闲刷新，逐次与稳定排序参考实现比较，核对无遗漏、重复及超限。该单路径基准不代表整体吞吐提升相同比例。

ARM64/x64 的 base、OpenSSL、eCaptureQ、CLI 竞态测试通过，x64 base vet 通过。从固定提交重新应用整套补丁后的 Linux 源码也通过 base 竞态测试，并与运行版本逐文件核对。ARM64 r38 探针 SHA-256 为 `2f9f03f78b37ae3caa5d81e3b0902f1ac2e045ffa15b55d440565def241870ed`，x64 为 `c243c1267b0467ebc97d5a13d0ebc618e2299e203a1e05ad0e81b9d9e5793f8d`；内核布局未变，继续使用已验证的七组 CO-RE 资产。

`functional-r38` 的 126 条请求/响应、正文、规则和 ZIP 核对全部通过，范围过滤、启动身份、动态撤销、空白名单、损坏配置拒绝及恢复再次通过；仍有两个 PCAP 序号缺口和一次排空未确认，整体完整性保持未验证。

`impact-network-r38` 使用独立 x64 Go 发流器、64 并发、约 2,526 请求/秒，各模式三十秒。baseline 有 3 个错误和 17 个调度丢弃；TLS 有 9 个调度丢弃、full 有 81 个调度丢弃，两个模式仍各发生三次 8 MiB 接收预算耗尽并最终后端 unavailable。TLS P99 约 6.54ms（基线约 6.01ms），full 约 7.60ms。该轮未通过，不能以解码/重排的单路径收益宣称持续采集或低影响验收完成。r36 使用 256 并发的诊断样本尾延迟及错误波动更大，也未通过；不同并发样本不用于直接计算性能改善。

### r36 eCapture 载荷分配

固定 16 KiB 内联 Event.Data 改为按紧凑载荷长度分配的独立切片，旧格式仍消费固定 16 KiB 数据区。Clone 深复制数据；失败解码清除先前载荷，禁止借用 perf-reader 缓冲区。eCaptureQ 同步 marshal 后将全新 wire 缓冲区交给 hub，通用 publish 仍复制调用方缓冲区。新增回归验证输入复用、Clone、短载荷重用及发布后调用方修改不影响已排队内容。

ARM64 同一紧凑事件解码基准各测三次：1 KiB 样本中位数从约 2.83µs/18,832 B/op 降至 1.326µs/1,600 B/op；128 字节样本分配为 704 B/op。最大 16 KiB 样本耗时约 3.1µs，与旧版相近。小载荷减少固定大对象，不代表持续吞吐门槛已通过。

ARM64 与 x64 的 OpenSSL、handlers、writers、eCaptureQ、CLI 竞态测试通过。r36 ARM64 探针 SHA-256 为 `97e018cafba85b6d89b888025e08f5405426f50a704f19e5daf9f9d3c84c83c4`，x64 为 `9a8ee62d5d227acb88c3993f7a77ab1120d5a8547a04007c76a8619e215fcc5f`。内核源码未变，核对后复用 r31 的七组 CO-RE 资产。整套补丁从固定上游提交重新应用成功，产出与测试源码一致。

`functional-r36` 的 126 条请求/响应、正文、规则及 ZIP 哈希全部通过，站点配置和进程身份未变；仍有两个 PCAP 序号缺口及一次 eCapture 排空未确认。原始传输范围过滤、错误启动身份、动态端口撤销、空白名单、损坏配置拒绝及恢复再次通过。整体完整性和排空保持未验证。

### r35 预加载队列与跨平台复验

原先后台消费者和全部 TLS 业务线程争用同一队列/连接锁。仅移除消费者对该锁的依赖后，CentOS r34 第十轮仍出现两次业务线程锁竞争丢失，因此未将该中间版本作为修复完成。r35 将队列改为固定 128 槽位的原子票据预留与独立消费，每个槽位分别标记可复用代次和发布代次；连接元数据使用 64 个分片，每片最多 64 项。正文复制、编码、传输和缺口格式化不持有连接锁。队列容量及 25µs 元数据锁自旋预算未扩大，预留最多尝试 64 次 CAS，失败仍有显式丢失诊断。传输恢复必须先交付缺口标记，后续正文才可继续。

ARM64 Debian、Ubuntu x64 和 CentOS 7 x64 均完成 `preload-acceptance-r35-0` 至 `r35-19` 连续二十轮，每轮 19 条，共 1,140 条请求及响应逐字节核对，含长连接、HEAD、中文、128 KiB 回显、四路并发、规则及证据 ZIP。三组均无已观测 TLS/队列/网卡丢弃或缺口事件，采集器停止后服务继续响应。完整性及端到端排空仍为 `unverified`；该样本不证明启动窗口、进程强制退出或持续高负载采全。证据保存到 `validation/optimization-20261117/*-preload-r35-*.json`，汇总为 `preload-r35-summary.json`。

原生队列回归覆盖首槽未发布时后槽不可越过、128 槽容量边界、四个生产者各 200 条事件的循环复用和逐生产者顺序、传输失败时未发布尾槽不可提前回收、恢复前缺口标记，以及 fork 后父队列保留/子队列重建。x64 GCC ThreadSanitizer 检查通过；由于 sanitizer 明确不支持多线程 fork 后重新创建线程，只在 sanitizer 运行时跳过 fork 块，普通原生回归仍执行该块。单元测试不代替真实服务 fork 故障矩阵。

预加载库以 Zig 为 ARM64/x64 分别交叉编译，目标 glibc 2.17，`-Wall -Wextra -Werror` 通过。对应产物分别在 ARM64 Debian 和 CentOS 7/OpenSSL 1.0.2k 各通过一次 19 请求验收。ARM64 测试机仍是新 glibc，不能据此宣称旧 glibc ARM64 运行矩阵全部通过。Linux 三台全仓库 Go 竞态测试及 vet 均通过。

### r33 持久化开销优化

ARM64 对同一 1 KiB HTTP 请求/响应配对基准各测三次：完整 TLS 帧的耗时中位数从约 48.1µs 降至 41.5µs，分配次数从 224 降至 195，分配字节约 44,621 降至 42,324 B/op。SQLite 批次内复用读写语句，并将旧记录解码收窄为告警历史。新增跨批次、大正文恢复、告警去重与扫描告警保留回归；既有回滚和保留期测试继续通过。基准不代表整条采集链路达到性能门槛。

`functional-r33` 的 126 条请求/响应、正文、规则及 ZIP 哈希核对全部通过，站点配置及进程身份未变。仍有两个 PCAP TCP 序号缺口和一次 eCapture 排空未确认，整体完整性保持未验证。Linux ARM64 和 Mac 全仓库竞态测试及 vet 通过，Windows x64 CGO 交叉构建通过。

跨机发流新增 Python/Go worker 与逐请求 JSONL 协议，控制端核对总数及结果，保存 worker 哈希。Go worker 的 HTTP/1 TLS 集成竞态测试在 Mac 和 x64 通过（测试服务允许 HTTP/2，确认发流器实际使用 HTTP/1）。Python 回归覆盖工作进程、截断账本拒绝、直方图量化误差及内存不随重复样本增长。

x64 Go 发流器向 ARM64 nginx 发送 2,000 请求/秒、十秒共 20,000 请求，错误和发生器丢弃均为零；4,000 请求/秒样本出现 194 个调度丢弃，不能据此宣称服务容量仅为 2,000。Python 发流器在 2,000 请求/秒已有明显调度丢弃。`impact-network-r33` 继续沿用旧回环容量参考、从 x64 发流约 2,526 请求/秒，各模式三十秒，仅作诊断：baseline 有 8 个错误和 14 个调度丢弃，TLS 有 5 个调度丢弃及三次接收预算溢出，full 有 33 个调度丢弃及三次接收预算溢出，吞吐和 P99 也未达标。正式验收仍未通过；控制端新增结束时 TLS 后端必须仍可用的检查，避免探针已退出但服务指标正常时误判通过。测试后 nginx 配置哈希及启动身份未变。

CentOS 7 r33 原生队列测试、全仓库竞态测试和 vet 通过。连续预加载验证前十八轮（342 条请求）通过，第十九轮 `preload-acceptance-r33-18` 因一次事件丢失未完成配对；原始诊断为 `recent_lock=1`，队列、端点和传输累计丢失均为零。已保留失败原始事件及缺口记录，不将此轮标记为二十次启停通过。该版本未解决稀有共享锁竞争；后续 r35 的修复及复验见上。

### 内核范围过滤及 x64 重复启停更新

ARM64 的 `kernel-scope-r30c` 直接读取 eCaptureQ 原始 protobuf，不经过采集器过滤。两个进程加载相同 libssl，并在不同回环地址监听相同端口；确认目标 PID/启动身份/端口的正向流量可见，而其他 PID、错误端口、错误启动时间、已移除端口、空 PID 白名单和损坏配置期间的六类标记均不可见。原子替换配置后等待探针应用确认，再发送验证流量；合法配置恢复后重新捕获成功。停止探针后测试服务继续响应。该结果证明此 ARM64/OpenSSL 3.5 样本的过滤行为，不证明负载门槛或端到端排空。

r30 探针 SHA-256 为 `097a93b43b0fcd85281487a896392d2c8ba068c6b4c73102aabe031c61d9e475`。此前 r29 已重新编译七个 OpenSSL CO-RE ABI 对象；r30 仅修改 Go 配置监听器并复用同版 BPF 资产。其余 ABI 的真实运行仍待验收；x64 构建进展见下。

干净源码重新应用全部补丁后，Linux ARM64 的 handlers、writers、eCaptureQ、OpenSSL 和 CLI 竞态测试全部通过。r31 修复 `/dev/null` 在停止时 `fsync` 返回 EINVAL 的问题，并复跑上述全部过滤与恢复检查通过，停止日志不再出现该错误。r31 SHA-256 为 `50c1d8d7e2f2c9a9ada7675fec97287aec9a2c2ae5b27f2f20f7f2498e4a4a83`，内核源码与 r29 核对一致后复用其 BPF 资产。报告及日志保存在 `validation/optimization-20261117/arm-kernel-scope-r31-*`。

Ubuntu x64 已从固定提交重新应用全部补丁并通过上述五组竞态测试，七个 OpenSSL CO-RE 对象均重新编译，探针完成静态 PIE 链接，SHA-256 为 `823781032751897c91a8bc8a98bb9c601500656c278e13995fa21488cdf13eb9`。测试机无法解析 GitHub 时，核对现有 libpcap 源码提交与 gitlink 均为 `104271ba4a14de6743e43bcf87536786d8fddea4` 后复制至隔离构建目录。此构建不证明对旧 glibc 的运行兼容。随后 `kernel-scope-r31` 在 x64/OpenSSL 3.5 实机通过与 ARM64 相同的九项过滤/恢复检查，且正常停止退出码为零，服务继续响应；证据保存在 `validation/optimization-20261117/x64-kernel-scope-r31-*`。

Ubuntu x64 `preload-acceptance-r29-0` 至 `r29-19` 连续二十轮各 19 请求全部通过，共 380 条，原生队列测试、Go 竞态测试和 vet 也通过。此结果取代下文 r5 的未修复状态；历史失败保留供追溯，不代表高负载或停止尾部已验证。控制端日志 `/tmp/traffic-lab-control/r29-192.168.1.10.log`。

启用内核范围过滤的 r31 短负载仍出现每连接 8 MiB 接收预算耗尽。TLS 模式完成 25,234 个客户端请求，P99 约 10.79ms（基线约 0.57ms），负载发生器丢弃 28 个调度；full 模式 P99 约 9.04ms、发生器丢弃 19 个调度。此样本既未达到性能门槛，也因同机发生器过载不能作为正式验收。紧凑事件及内核过滤尚未解决持续吞吐瓶颈。测试前后已核对 nginx 配置哈希、PID 和进程启动时间未变。结果保存在 `validation/optimization-20261117/arm-impact-smoke-r31-results.json`。

### 重复启停、命名空间及负载预检

后续输出链路修复增加独立、有界的 WebSocket 接收队列，以及异常断开/超限的传输缺口和占用诊断。`impact-profile-r19` 的诊断表明原 1024 项队列在 828,267 字节时先达到条数上限，因此保留每连接 8 MiB、全局 32 MiB 字节预算并将条数上限改为 16384。原始接收顺序、单连接/全局预算及提前退出释放的竞态回归通过。

eCapture 新增丢弃文本时跳过格式化的独立补丁，Linux ARM64 的输出 handler、writer、eCaptureQ 和 OpenSSL 定向竞态测试通过，并在固定上游提交的独立 checkout 构建 `bin/ecapture-r13`，SHA-256 为 `5a3f87a3052a2c144879b466188a08d26392814b693aac9de44cb4ac2d82a5e1`。复用了原实验环境已生成的 ARM64 字节码，编译前核对对应 `kern/openssl.h` 一致；这不代表新增 OpenSSL 1.1.1 ABI 已构建或验收。

事务身份改为从已校验的 eCapture 事件传递，恢复响应时保留原请求启动身份，回归覆盖 PID 重用后不重新归属旧证据。串行 TLS 响应先到时不再等待同队列中的请求，网卡双向并行路径仍保留等待。PCAP 新增 256 KiB 输出缓冲及轮换/停止排空与同步，回归核对小包尾部跨轮换保存。

最新 `functional-r18` 使用该 eCapture 探针和更新后的采集器完成 126 条请求及响应全部配对、逐条正文核对、五类规则与证据 ZIP 哈希校验。站点配置及 PID 保持一致，已观测 TLS/用户队列/网卡丢弃均为零。另有两个 `pcap/tcp_sequence_gap/events` 和一个 `ecapture/drain_unconfirmed/shutdowns`，因此整体完整性及排空仍为未知。报告已保存到本地 `validation/optimization-20261117/arm-functional-r18-verification.json`。

这些功能回归不能证明高负载已修好。r10/r11/r13/r16 的约 2526 请求/秒短样本均未通过全部性能门槛，仍有传输中断、接收队列溢出及显著 P99 增幅。短配额周期试验未改善关键指标，已撤回，CPU 百分比与原周期保持原值。另用独立诊断构建采集主进程 CPU/阻塞/锁 profile 及 eCapture 启动后两秒的 CPU profile；profile 记录不作为性能验收结果。

`impact-smoke-r21` 在扩大接收条数上限后不再有采集器接收队列超限。该轮 packets 门槛通过（25262 个请求，P99 约 0.62ms，baseline 约 0.42ms），但 tls 和 full 仍未达标：各有三次传输中断，TLS 事务诊断数分别为 1323 和 1018。探针日志明确记录 `ecaptureq backpressure: client queue full`，并有 perf 丢失；下一处瓶颈已缩小到 eCapture 发送侧队列，尚未修复。已取回 `arm-impact-smoke-r21-results.json` 和环境记录，再次核对原 nginx 配置、PID 和启动时间未变。短时单轮结果仍不能作为正式性能验收。

ARM64 的 `preload-acceptance-r8-0` 至 `r8-19` 连续 20 轮全部通过，每轮 19 条请求，共 380 条请求及响应逐字节核验，状态中无缺口事件。采集器 SHA-256 为 `81e8ba694a0a46895c25d5c3a3a9632da68976ab1f744c95f8fac8934d1f17b9`，预加载库为 `ff09ba465fb08c050d88318b4fe4a35a5cd33b38720f1947208a9ff0d2636d5f`。该结果只覆盖独立预加载测试服务，各后端端到端排空仍未确认。

在此之前，r7 第十轮暴露一次锁竞争丢失（诊断 `recent_lock=1`，队列、端点及传输失败均为零）。原始正文复制和后台编码改为在共享锁外执行，以槽位预留及发布标志保证 FIFO；新连接端点查询也移至锁外。原生 `queue_test.c` 验证未发布槽位阻止后续事件越过，以及传输失败时未发布槽位不会被提前复用。该测试已加入 Linux ARM64/x64 CI。

`netns-r9b` 使用 `unshare --net` 创建独立测试命名空间，通过 `--netns-pid` 捕获一条 HTTP 请求及响应，状态中 12 个包、一条完整事务、无已观测丢弃。核对采集器主线程仍在宿主命名空间，采集停止后测试服务仍响应。该样本不证明容器 TLS、挂载命名空间或进程发现矩阵通过。新增入口为 `scripts/linux/verify-netns.py`。

性能预检先在无采集器运行时按 4/8/16/32 并发各测十秒，回环 HTTPS /api/echo 的最高成功吞吐约 8,421 请求/秒，随后以其 30%（约 2,526 请求/秒）执行 baseline/packets/tls/full 各十秒。`impact-smoke-r8` 未达门槛：packets P99 约 6.57ms、tls 约 6.26ms、full 约 16.34ms，baseline 约 0.31ms；压测端调度丢弃分别为 944、3、4。TLS 模式还因 128 项原始证据队列在约 334 KiB 占用时耗尽而停止。已将项目数上限改为 2048，保持每写入器 4 MiB、全局 32 MiB 字节预算，并增加 512 个小事件突发回归；待复验。这些短样本及同机负载发生器不能作为正式容量或低影响验收结论。

`impact-smoke-r9` 同负载复验不再出现证据队列溢出或采集失败。packets 该轮全部门槛通过（P99 约 0.49ms，baseline 约 0.28ms）；tls P99 约 18.51ms、full 约 11.48ms，均未达标。TLS 模式压测端调度丢弃 64，full 无调度丢弃但目标 CPU 增量超过单核 5%。两种 TLS 模式均有大量已观测 TLS 丢失及非正常期间的 WebSocket 断连重试，尚未完成逐请求账本核对；不能宣称高负载采集完整。下一步需处理 eCapture 输出背压及资源预算，不能以缓冲扩大代替持续吞吐和低影响验收。

测试前后 nginx 配置 SHA-256、master/worker PID 及启动身份完全一致。上述 20 轮报告、容量与影响记录已取回本地 `validation/optimization-20261117/`（Git 忽略目录）。

测试源码目录为三台用户测试机上的 `/opt/traffic-lab-20261117-7481e4c3/src`，测试产物与原有站点隔离。Debian ARM64（192.168.1.7）、Ubuntu x64（192.168.1.10）及 CentOS 7 x64（192.168.1.12）的优化版本全仓库竞态测试通过；CentOS 7 使用离线依赖完成原生构建。

ARM64 的 `preload-acceptance-r3` 完成 19 条 HTTPS 请求及响应逐字节核对，包括长连接、HEAD、中文、128 KiB 回显、四路并发、告警、可信代理及证据 ZIP 校验。已观测三类丢弃均为零，采集器停止后服务继续响应。采集器 SHA-256 为 `cc06373d0810c316df6973f08c90b87f19a59e837901a48a6e5819c56c461d40`，预加载库为 `082de632fb8124f71e56ed0729bdb1cc10214573ae177e25afa4eac4c282db62`。完整性及排空仍为 `unverified`，此样本不证明启动窗口或退出尾部采全。控制端记录在 `/tmp/traffic-lab-control/arm-r3.log`。

CentOS 7 的 `preload-acceptance-r4` 未通过：19 次客户端请求仅形成 7 条事务，探针报告 45 个丢失事件，不能将事件数当成请求丢失数。后台发送线程的背压等待从 100ms 延长至 1 秒后，`preload-acceptance-r5-0`、`r5-1`、`r5-2` 连续三轮各 19 条 HTTPS 请求及响应全部核对通过，TLS、用户队列及网卡丢弃均为零，导出 ZIP 校验通过。该等待发生于发送线程，业务线程队列及锁等待上限保持不变。cgroup v1 状态显示采集器限制为 256 MiB、单核 50%，目标服务未移入该组。三轮各有一个 `pcap/tcp_sequence_gap/events` 诊断，仍待核查，不能据 HTTPS 验收宣称 PCAP 无缺口。

CentOS 7 r5 采集器 SHA-256 为 `5b63e9eef07b1700b3fbfd472859a0dd8a704e27502ba15d38104ef158effa25`，预加载库为 `c206a2c5f818cd2f7900e318f7ceb02cef2bdb3ca6ac2ba480a0e8ba18975e21`。控制端记录在 `/tmp/traffic-lab-control/centos7-r5.log`，失败会话保留用于比对。

PCAP 核查发现 r5 有两个实际 65,549 字节的回环帧被 65,535 字节快照截短。将各平台实时快照统一为 256 KiB，并增加截短帧缺口计数后，CentOS 7 `preload-acceptance-r6-0` 的 19 条请求再次全部通过，状态中不再有 TCP 序号缺口或其他缺口事件。r6 采集器 SHA-256 为 `48fa4e6125d45219b8a200bc81378300cc708617e2a7b25a6cd55a969f3f45f9`，库与 r5 相同，记录在 `/tmp/traffic-lab-control/centos7-r6.log`。

Ubuntu x64 SSH 重连成功，竞态测试及静态检查通过，但 `preload-acceptance-r5` 未通过：128 KiB 正文期间报告一个探针事件丢失，形成 20 条记录，其中有不完整正文和片段。四路并发记录也带有丢失后的不完整标记。尚需定位锁竞争或其他丢失来源，不能宣称新版 x64 全部验收通过。

新增保留期清理与活动 SQLite 批次共用事务的回归，本地及 ARM64 全仓库竞态测试、`go vet ./...`、Python 影响比较与预热脚本测试及差异空白检查通过。本轮还未形成正式低影响、八小时长压、HTTP/2 实机或 Windows 新版本验收结论；二十次启停仅覆盖上述 ARM64 独立预加载服务。

## 2026-11-16 Debian 13 / nginx 系统级预加载与漏洞靶场

在用户提供的 `192.168.1.7` 搭建并验证。目标机为 Debian 13 (trixie)、Linux `6.12.107+deb13-arm64`、2 核 2 GiB、nginx 1.26.3、OpenSSL 3.5.7、glibc 2.41，使用 Go 1.26.11 在目标机原生构建 `traffic`、`traffic-console` 和 `libtraffic-openssl.so`。既有 `traffic-lab` 站点和 18080 服务保持运行，仅新增独立站点和配置。

新增内部 CA 与服务器证书，SAN 为 `traffic-lab.local`、`acme-lab.local`、`192.168.1.7`、`127.0.0.1`，CA 安装到系统信任库。nginx 以 TLS 1.2 和 TLS 1.3 提供 443，证书链校验 `ssl_verify_result=0`。新增 `acme-lab.service`（www-data，127.0.0.1:18081）和 `/acme/` 反向代理，站点包含真实可利用的 SQL 注入、命令注入、路径穿越、SSRF、反射 XSS、任意文件上传和敏感文件暴露；原有 18080 测试站未修改。

eBPF 路径使用固定版本 eCapture 与项目补丁。外部客户端经 `enp0s5` 访问时，13 条 HTTPS 请求全部还原为 `backend=openssl`，命中 SQLI-001、XSS-001、SSRF-001、FILE-001、PATH-001、CMD-001 与响应侧 RESPONSE-PASSWD-001/RESPONSE-CMD-001，TLS 1.2/1.3 均覆盖。节流到约 2.5 请求/秒时 10 条请求采集 9 条，两个 worker 的事件均到达。突发 20 条请求时仅 5 条形成事务，`tls_dropped` 仍为 0，说明存在未上报的突发缺口；完整性继续标记 `unverified`。曾尝试按 PID 启动多个 eCapture 实例，实测两个实例对同一 `libssl.so.3` 的 uprobe 会互相覆盖，事件被单个实例的 PID 过滤器丢弃，因此保留按库+UID 分组，不采用每 worker 一个实例。

`LD_PRELOAD` 路径先由仓库自带 `verify-preload.py` 完成 19 条请求、128 KiB 回显、四路并发、告警和证据 ZIP 校验，`tls_dropped`、`queue_dropped`、`dropped` 均为 0。随后验证系统级 `/etc/ld.so.preload`：配置 `socket=/run/traffic/plaintext.sock`、`targets=nginx`，采集器使用 `--openssl-preload-allow-uid 33`。socket 为 `0660 root:www-data`，父目录 `0755`；nginx master 重启后两个 www-data worker 均加载库。11 条 HTTPS 请求全部采集为 `backend=openssl-preload`，命中 9 条告警，包含 WEBSHELL-UPLOAD-001，TLS 1.2/1.3 均覆盖，`tls_dropped=0`。未匹配的 curl 进程保持惰性，未产生事件。删除 `/etc/ld.so.preload` 并重启 nginx 后，worker 的 `/proc/PID/maps` 不再包含该库，站点和证书访问保持正常。

本轮根据实测修正四处预加载逻辑：`/etc/ld.so.preload` 无法设置环境变量，新增 `/etc/traffic/openssl-preload.conf` 的 `socket`/`targets`/`debug_file` 配置；非匹配进程保持惰性，避免系统级预加载影响 sshd 等无关 TLS 客户端；新增 `--openssl-preload-allow-uid`，socket 归属服务账号主组并接受该 UID 的内核凭据；采集器自动创建 socket 父目录并修正私有 umask 导致的 `0700` 目录，使非 root worker 可连接。回归覆盖 UID 解析、目录创建与权限、凭证校验和进程身份。

边界：eBPF 突发流量存在未上报缺口，需要单独定位 perf/WS 背压；预加载需要重启目标服务，`nginx -s reload` 不会重新加载 master 的库；HTTP/2、HTTP/3、静态链接 OpenSSL、Go TLS 和长期压力未验证。测试期间 `traffic-lab` 与 `acme-lab` 均保持可用，证书、站点配置和 nginx 进程身份在回滚后核对一致。

## 本轮采集优化代码验证

新增缺口记录、连接局部淘汰、HTTP/1 配对边界及大正文排空、HTTP/2 有界解析、Java/Windows 探针序号与退出状态、预加载热路径调整、只读预检和资源配置。实现、测试入口及尚未完成的计划项见 [优化实施与验收](OPTIMIZATION.md)。

本轮仅完成本地自动化检查与交叉构建，不改变下面既有实机样本的覆盖范围。HTTP/2、cgroup v1、网络命名空间、更新后的探针及性能门槛仍待目标平台实测；未重新执行 Linux/Windows 故障注入或长压。


## 2026-11-13 CentOS 7 旧内核 OpenSSL 预加载后端

在用户提供的 `192.168.1.12` 原生构建并测试，环境为 CentOS 7.9.2009、Linux `3.10.0-1160.119.1.el7.x86_64`、glibc 2.17、GCC 4.8.5、Python 3.6.8、OpenSSL 1.0.2k-fips。项目使用 Go 1.26.11，在目标机动态链接系统 libpcap 构建采集与分析程序，采集程序的 glibc 符号需求最高为 `GLIBC_2.14`，已在该机器执行成功。

新增 `native/openssl-preload/traffic_openssl.c`、构建脚本 `scripts/build-openssl-preload.sh`、Linux Unix datagram 接收后端及 `scripts/linux/verify-preload.py`。库拦截实际完成的 OpenSSL API 读写，通过 128 条有界事件队列和发送线程传输至采集器。接收端校验内核凭据及 PID/进程启动时间，保存原始事件并复用现有请求响应解析、规则和证据导出。测试服务使用目标机 Python 的动态 OpenSSL，仅监听随机回环端口。

最终样本位于目标机 `/opt/traffic-centos7-test/accepted`。19 条请求逐字节核对请求及响应正文通过，涵盖同一 HTTPS 长连接、HEAD、中文 POST、128 KiB POST/回显和四路并发的 12 条独立连接请求。SQLI-001 和 RESPONSE-PASSWD-001 分别命中一次，可信代理来源与直连端点保留正确。证据 ZIP 中的 SHA-256 清单通过逐项核验。客户端发起的 19 条请求均形成完整且未截断的记录，已观测网卡、队列及 TLS 丢弃均为 0。停止采集器后再次访问服务成功，随后测试脚本停止自己的服务，测试端口已关闭。

最终采集程序 SHA-256 为 `7f42bb539bc2ce2f2798f11d41586daec3ca5f7ce610e6551cbfda58662c7552`，预加载库为 `bf1ef97849be33f171775d2e13baa5688ca1458e2ee5a5554cd67438f7ccb17d`。报告、网络包、明文事件、索引及导出包保留在验收目录。

CentOS 7 全仓库 `go test -race ./...`、`go vet ./...` 通过。新增回归验证 socket 路径保护、内核发送凭据、伪造进程身份拒绝、响应规则与 socket 清理。macOS 全仓库竞态测试、静态检查及 Windows x64 交叉构建和静态检查通过。Linux CI 新增采集库编译及测试脚本语法检查。

首轮直接 datagram 发送在大正文与并发下出现丢弃，改为有界异步发送后重测通过。测试脚本改用 `traffic-console requests/show/export` 读取和核对索引，兼容 CentOS 7 自带 Python SQLite 无法识别部分索引的问题，并显式使用 UTF-8 读取状态报告。

该方案要求在目标服务启动时设置 `LD_PRELOAD`，库驻留于服务进程直到退出。socket 限制为采集器相同 UID。现有 cgroup v2 资源限制在该 cgroup v1 主机报告 `unavailable`。测试期间安装了 libpcap-devel，工具链、源码和测试产物存放于 `/opt/traffic-centos7-test`，使用独立目录中的临时 Vault 仓库配置安装依赖。目标机系统服务配置保持原有值。

本次覆盖动态 OpenSSL 1.0.2k、HTTP/1.1、TLS 1.2 和独立测试服务。Nginx、Apache、自定义无 socket BIO、其他库版本、进程 fork 后的采集、异常退出、长期压力与性能仍待分别验证。`SSL_read_ex` / `SSL_write_ex` 已提供拦截入口，但 OpenSSL 1.0.2k 缺少这些 API，本次样本覆盖 `SSL_read` / `SSL_write`。进程崩溃、`_exit`、发送队列未能最终送达等缺口仍可能未知，完整性状态保持 `unverified`。


## 2026-11-12 P0 检测与完整性改进

新增常见 XSS、SSRF、XXE、SSTI、JNDI、反序列化、Webshell 上传及访问特征，并检测响应中的 passwd、命令输出特征。规则支持请求或响应的完整消息、全部头部、单个头部及正文，gzip 正文有界解压后检测。回归覆盖字段隔离、Host 和重复头部、压缩响应、响应补全后的告警，以及相同命中数量下规则变化时的告警外送。

可信代理回归覆盖非可信对端伪造转发头、代理链右侧信任边界、重复 X-Forwarded-For、X-Real-IP、IPv6、非法头部、请求响应补全时身份保留。证据导出的 PCAP 筛选改用保留的直连端点，既有平铺及新目录布局的导出测试均通过。

状态新增 TLS 网卡外层记录与明文请求诊断计数。实际漏采请求估计保持 `null`，完整性为 `unverified`，TUI、Web 和证据包显示未知范围。两类计数的单位不同，不能相减得到漏采数。IIS 附加窗口和 Apache 既有阻塞读取的实际启动缺口仍待独立量化。

新增可选 Webhook 外送。回归验证异步发送、503 重试、重试幂等键、更新去重、重定向失败与投递计数。本地测试仅发送合成告警到回环 HTTP 接收器。队列位于内存，退出等待和重试有界，失败与队列溢出计数保存在状态中。

本机 `go test -race ./...`、`go vet ./...`、Windows x64 两个程序的 CGO 交叉构建及 `go vet` 通过。macOS 默认 SDK 27 与当前系统链接器不兼容，本次构建和测试通过环境变量使用已安装的 SDK 14.4。Java 17/21 Maven 测试及打包通过。CI 新增 Windows 原生测试和构建及 Java 17/21 任务，远端执行结果待验证。Windows 托管任务显式跳过两个依赖 Npcap DLL 的离线集成测试，这两项在 Linux 任务中执行。

Chrome 实测持续写入 SQLite WAL 的测试会话。保持页面打开后新增请求，累计请求和请求列表自动从 0 更新到 1。保持待响应详情打开后写入响应，列表及详情自动更新为 200，告警页签及检测依据计数更新为 1，并显示直连地址与来源头部。该样本由测试写入器生成。当前本地账户无法打开 `/dev/bpf0`，`sudo` 需要交互密码，因此真实网卡采集到浏览器的完整链路仍待验收。

本轮进展覆盖 P0 可观测性、常见规则、可信代理、CI 和 Webhook。HTTP/2、HTTP/3、WebSocket、Go TLS、Tomcat NIO2、IIS TLS 1.3 与应用池回收等协议和服务能力，以及 Linux x86_64 多服务实测、大正文、高带宽、多网卡和长期性能，仍需后续实现或验收。


## 2026-11-12 Windows Nginx / Apache 开发验证

在同一台 Windows 10 LTSC 17763 x64 测试机上新增独立的 Nginx 1.28.0 官方 x86 二进制和 Apache Lounge 2.4.71 x64 实例。Nginx 测试端口为 18080/18443，Apache 为 18081/18444，Python HTTP/1.1 回显后端为 18090，验收通过回环地址访问。服务在附加前启动，测试过程保持工作进程身份和两份站点配置哈希。

Nginx 静态 OpenSSL 的函数入口由内置二进制 profile 解析，文件 SHA-256 为 `53530836391897ea218d8040acdd467cd4832efab597e534d7c670e0e6c94b3c`，先校验整个文件与函数入口再拦截。Apache 使用导出的 `libssl-3-x64.dll` API，mod_ssl 自定义 BIO 的套接字通过 `SSL_get_ex_data`、`ap_get_conn_socket` 和 `apr_os_sock_get` 取得。

最终 62 条 HTTP/1.1 请求及响应全部比对通过，包括 12 条 HTTP 和 50 条 HTTPS / TLS 1.2、1.3。覆盖保持活跃的附加前既有连接、中文 POST、分块响应、HEAD、404、四路并发、大响应截断后的下一条请求及 SQLI-001 告警。另发出 29 条保持原连接活跃的附加预热请求，其中 10 条被记录，最终会话共 72 条记录、1163 个网络包、6 次告警，网卡、队列和 TLS 已观测丢弃计数均为零。预热包含探针尚未就绪时的流量，不能据此声称无启动缺口。

两个 helper 均报告 `hooks_removed=true`、`script_unloaded=true`、`transport_detached=true`。测试前后 Nginx worker 身份为 `8972:134389675973912963`，Apache worker 为 `8880:134389676868048643`，配置哈希保持一致。最终二进制在同一批工作进程上完成重复附加与采集，验收中保持服务运行。期间一次网络连接中断后已重新连接并取回成功报告，主机启动时间及服务进程保持一致。

HTTP 联测发现并修复三个共享解析问题。收发方向并行时，HEAD 响应需要先取得请求方法。正文超过保存上限时，需要排空剩余正文并继续处理同连接后续消息。回环小分片突发可能用尽单流 16 个槽位，现调整为 256 个槽位，全局正文队列仍限制为 32 MiB。新增请求方法通知和有界等待、截断后续响应和 OpenSSL 丢失边界回归测试。

指定 Python ctypes 测试进程 PID，外部调用 `SSL_read_ex` / `SSL_write_ex`，TLS 1.2、1.3 两条请求均还原为 backend `openssl`、状态码 200，丢弃计数为零。OpenSSL `s_server -www` 的内部 BIO 路径另外测试为未取得明文，不能将 DLL 导出 API 的验收推广到所有 OpenSSL 调用路径。静态 profile 缺失的故障注入通过，目标状态为 `unavailable`，同一 Nginx 的 HTTP 请求仍完整采集为 backend `pcap`。

本地全仓库 `go test -race ./...`、macOS 与 Windows `go vet ./...`、Windows x64 交叉构建通过。Windows 实机的进程身份、监听端口所有权、Nginx/Apache 名称识别、通用 PID 发现、既有 IIS assembler、OpenSSL 丢失边界、HEAD 并行解析及截断后续响应测试通过。分析程序的服务及规则筛选、HTTPS 请求导出和 ZIP 内 SHA-256 清单核验通过。

完整成功报告和会话在测试机 `C:\traffic-lab\validation\middleware-final`、`middleware-generic-api` 和 `middleware-fallback`，本地证据在 `validation/windows-middleware/`，主会话另保存到 `sessions/192.168.1.11/2026-11-12/windows-middleware-final/`。证据、二进制和测试私钥在 Git 忽略目录中。测试站点保留运行，测试采集器及辅助进程在验收结束后退出。

当前限制包括动态附加前已进入的调用和半截消息、其他静态 Nginx 版本、其他自定义 BIO、HTTP/2、HTTP/3、Windows Go TLS/JSSE、模块热替换和长期性能。启动预热用于保持原连接并等待附加。其他中间件需要各自实机验证。

## 2026-11-12 Windows x64 开发验证

测试机为用户指定的 `192.168.1.11`，Windows 10 企业版 LTSC、版本 `10.0.17763`、x64，已有 Npcap。Windows 时钟显示 `2026-01-14` 附近，与开发机日期不同，采集时间保留测试机原值。

Windows 两个可执行程序使用 Go 1.26.11、CGO、x64 MinGW GCC 交叉构建。已在测试机运行采集器、分析器和共享会话测试，包括 Windows 进程身份、IIS 配置绑定解析、文件锁互斥、证据 ACL 继承、中文及特殊字符路径。

独立的临时 Python HTTP 站点完成 56 次 HTTP/1.1 请求验收，涵盖中文 POST、分块请求响应、长连接、四路并发、大正文截断及五类规则。最终会话有 56 条请求及响应、732 个包、7 次告警，网卡、用户态队列及 TLS 丢弃计数均为零。证据 ZIP 内 SHA-256 校验通过，强制结束另一采集进程后可重新取得文件锁并导出证据。Job Object 报告内存与 CPU 限制生效。临时站点和采集进程均已停止。

首轮实机大正文暴露 Npcap 回环帧长达 65,539 字节，原来的 65,535 字节抓包上限丢失最后四字节。Windows 抓包快照现为 256 KiB，循环 PCAP 和导出 PCAP 保留原快照上限，已添加大帧保存与导出回归检查。

首次安装重启后，IIS 10 的独立 `TrafficLab` 站点已完成搭建，HTTP 8080、HTTPS 8443，健康检查均返回 200。测试机时钟已恢复为实际日期。测试期间 `w3wp.exe` 始终为 PID 4168、进程身份 `4168:134389596627817116`，站点、处理器代码、静态文件和 applicationHost.config 的 SHA-256 保持一致，无应用池回收或采集引起的配置修改。

IIS 动态明文后端使用 Frida 17.5.1 和 HTTP Server API，已接入 `traffic capture --iis-probe ... --iis-runtime-dir ...`。IIS 身份需要读取探针临时目录，使用专用 `probe-runtime` ACL 修复了最初的附加失败。异步接收在 I/O 完成后读取，通过请求 ID 关联正文及响应，处理并发响应先于接收事件到达、分块响应解码和文件实体复制。API 原始事件保留在 `tls/iis-*.jsonl`，SQLite 记录 backend 为 `iis-httpapi`。

最终请求矩阵包含 53 次 HTTP 和 54 次 HTTPS / TLS 1.2，107 次请求响应均通过正文比对。另发出 24 次显式预热请求，采集到 14 次，漏采 10 次。最终会话共 121 条记录、2089 个网络包、13 次告警，网卡、队列及 TLS 已观测丢弃计数为零。启动漏采单独记录，不能由丢弃计数推断所有请求均被捕获。中文 POST、分块请求响应、文件响应、长连接、四路并发、大正文截断和五类规则通过，采集启动前建立的 HTTPS 连接继续复用。ZIP 校验通过。

停止时动态脚本移除所有拦截，并逐个核对入口及返回位置的原始指令字节已恢复。实测存在 Frida 脚本卸载或传输断开等待未完成 IIS I/O 的情况，报告中 `hooks_removed=true`，但 `script_unloaded=false`、`transport_detached=false`。辅助进程在恢复指令后有界退出，目标中的 Frida 运行时可能继续保留，完整运行时卸载尚未通过验收。

强制结束采集器后，辅助进程通过控制管道 EOF 停用，在相同 IIS 工作进程上重新附加、再次采集、正常停止及缺失辅助脚本的故障回退检查通过。重复附加测试 24 次请求中记录到 14 次，启动窗口仍单独计入边界。

当前边界包括附加启动窗口漏采、内核缓存直接命中、HTTP/2、TLS 1.3、应用池进程替换、长期性能和完整运行时卸载。Windows 10 17763 本次仅验证 HTTP/1.1、TLS 1.2 及既有同一工作进程。动态后端需要显式启用，不应声称无启动缺口或已完整卸载。

本地程序在 `bin/windows/`，完整会话与实机日志在 `sessions/192.168.1.11/2026-11-12/` 和 `validation/windows-amd64-2026-11-12/`，测试机部署在 `C:\traffic-lab`。macOS 竞态测试、Windows 采集器回归及两平台静态检查通过。本次 Linux 原生构建尚未重验。IIS 实验站点保留运行，采集与辅助进程在测试后退出。

## 2026-11-12 Linux x86_64 验证

在用户指定的 `192.168.1.10` 原生构建并测试，环境为 Ubuntu 26.04 LTS、Linux 7.0.0-29-generic、x86_64、Nginx 1.28.3、OpenSSL 3.5.5，内核 BTF 可用。构建源码与独立实验站位于 `/opt/traffic-x64`，实验站仅监听回环地址。采集和分析程序使用 Go 1.26.11，eCapture 使用 Go 1.26.0、Clang 21 构建，固定上游提交与 ARM64 相同。

- `go test -race ./...`、`go vet ./...` 和两个程序的构建通过。
- eCapture 的 OpenSSL 3.0.0、3.0.12、3.5.0 CO-RE 字节码及 x86_64 可执行文件构建通过。OpenSSL、基础探针、事件发布处理器和 eCaptureQ 定向竞态测试通过，完整补丁在干净的固定上游源码上通过应用检查。
- `scripts/verify.py` 完整验收通过，126 条请求及响应全部配对，均无不完整或截断标记，覆盖 HTTP、TLS 1.2/1.3、中文 POST、并发、长连接与采集前已建立的 HTTPS 连接。
- 五类规则触发，正常 POST 无告警，导出 ZIP 的 SHA-256 清单核对通过。实验 Nginx 配置哈希及原有进程身份检查通过。
- `scripts/verify-services.py` 的 Nginx 六条串行访问通过，包含已有 HTTPS 连接、UTF-8 中文正文和采集运行中的响应查询，验证空闲时末批 TLS 数据及时写入。
- 两组最终会话的网卡、用户态队列及 TLS 丢弃计数均为零，cgroup v2 的 256 MiB 内存和单核 50% CPU 约束生效。

首轮实测发现多核 perf 事件乱序，一条请求的正文先于请求头送达，形成额外的不完整记录。采集器现启用 100 毫秒排序窗口，eCapture 补丁增加读取超时后的末批刷新，修复后完整验收与运行中查询均通过。排序带来约一个窗口的事件缓冲时间。首轮失败证据保留在测试机 `/opt/traffic-x64/validation/functional`。

最终二进制位于测试机 `/opt/traffic-x64/bin/` 和本地 `bin/linux-amd64/`，附带 `SHA256SUMS`。本地完整会话位于 `sessions/192.168.1.10/2026-11-12/functional-final` 与 `nginx-live`，日志及证据 ZIP 位于 `validation/linux-amd64-2026-11-12/`。文件均在 Git 忽略目录中。验收结束后已停止实验 Nginx 和后端、退出采集探针，并禁用新安装 Nginx 的系统服务自启动。构建依赖和验证文件保留以便复核。

本次 x86_64 运行验收覆盖 Nginx / OpenSSL 3.5。OpenSSL 3.0 探针已编译，Apache 自定义 BIO、Tomcat Java Agent、通用 OpenSSL API、其他发行版及长期性能尚未在 x86_64 实机验收。采集器与分析程序动态依赖构建环境的 glibc，采集器还依赖 libpcap，其他发行版建议在目标环境重新构建。

## 2026-11-12 多服务验证

在同一台 Debian 13 ARM64 / Linux 6.12 主机上使用独立实验实例，按普通 Web 访问验证本次多服务改动。每组主要验收发送六次串行 GET/中文 JSON POST，包含 HTTP 和 HTTPS。各组成功样本的请求、响应完整，已观测网卡、队列和 TLS 丢弃均为零。新增 Java Agent 的 JVM 内开销尚未形成性能验收结论。

| 服务 | 实测环境 | 验收结果 |
| --- | --- | --- |
| Nginx | 原有 1.26 / OpenSSL 3.5.7 | 6 条，已有连接通过，原配置和进程身份保持一致 |
| Apache event | 2.4.69 / APR 1.7.5 / OpenSSL 3.5.7 | 6 条，已有连接通过 |
| Apache worker | 同上 | 新连接 6 条通过，已有阻塞读取存在首次漏采 |
| Apache prefork | 同上 | 新连接 6 条通过，已有阻塞读取的完整性尚未验收 |
| Tomcat 9 | 9.0.123 / Temurin 17.0.21 / JSSE NIO | 6 条，已有连接与重复附加通过 |
| Tomcat 10.1 | 10.1.61 / Temurin 21.0.13 / JSSE NIO | 6 条，已有连接通过 |
| 非 root Tomcat | 10.1.61 / JDK 21 / UID、GID 33 | 6 条，凭据切换、临时 JAR 和令牌路径通过 |
| HAProxy | Debian 13 软件包 / OpenSSL 3.5.7 | 指定 PID 的通用 OpenSSL 采集 6 条通过 |
| 外部 OpenSSL API | OpenSSL 3.0.20 / C 测试服务 | `SSL_read_ex`、`SSL_write_ex` 的 TLS 1.2/1.3 两条 GET 通过 |
| 同会话多服务 | Nginx + Apache prefork + Tomcat 9 | HTTP、HTTPS 各一条，共 6 条，后端和服务归属正确 |

TLS 探针不存在、Java 附加助手失败两种实机故障注入通过，目标状态报告不可用并继续保存正常 HTTP 请求。

`go test -race ./...`、`go vet ./...` 在 Linux ARM64 和 Mac ARM64 上通过。Java Agent 的测试覆盖直接缓冲区、多缓冲区、实际消费/产生字节、加密输出缓冲区排除、队列溢出和线程标记清理。eCapture 补丁通过定向竞态测试，包含 Apache 自定义 BIO 元数据与连接代次解码。三组 OpenSSL CO-RE 字节码构建并完成实际内核挂载。

本地完整会话位于 `sessions/192.168.1.7/2026-11-12/`，包括 `14-19-02-multi-services-final`、`14-20-38-tomcat-nonroot-ready`、两组 Apache 新连接样本及 OpenSSL 3.0 样本，可直接使用无参数 TUI 选择。多服务会话的服务筛选、Java 请求详情和证据导出已验证，ZIP 内 SHA-256 清单核对通过。原始证据保存在 Git 忽略目录中。

### 当前边界

- Apache worker/prefork 在采集前已经进入阻塞 `SSL_read` 的调用，入口参数无法由后附加的 uprobe 回溯，首次返回可能漏采。worker 实测丢失该请求并记录 TLS 元数据缺口，新连接测试使用显式 `--new-connections-only`，报告记录已有连接未测试。
- Apache 自定义 BIO 的结构读取针对 Apache 2.4 / APR 1.7 / OpenSSL 3.5 ARM64，并核对 BIO 方法名。其他组合需要验收。
- OpenSSL 3.0 的 `s_server -www` 内置 BIO 路径未取得明文，尚未完成原因定位。外部导出的 SSL API 调用已通过，不能据此认定所有使用 OpenSSL 的程序均可采集。
- Tomcat 支持独立部署的 NIO Connector。NIO2、其他 Java 服务、HTTP/2、HTTP/3 和 WebSocket 内容解析继续待适配。Agent 停用和重复附加已测，类本身保留在 JVM 内，暂不支持 Agent 热升级。
- 新服务的队列与资源限制已有代码约束，过载、所有 JVM 禁止附加组合、容器网络及所有异常退出路径尚未完成实机验收。

## 2026-11-11 Nginx 历史验证

验证环境为 Debian 13 ARM64、Linux 6.12、Nginx 1.26、OpenSSL 3.5，内存约 2 GiB。记录日期为 2026-11-11。

## 已执行

- 主程序通过 Linux `go test -race ./...`、`go vet ./...` 和构建。
- 补丁后的 eCapture 通过 OpenSSL、事件发布处理器和 eCaptureQ 的定向竞态测试，ARM64 OpenSSL 3.5 CO-RE 构建和真实内核挂载成功。
- 126 条实机请求全部捕获并配对响应，覆盖 HTTP、TLS 1.2、TLS 1.3、中文 POST、并发、长连接和工具启动前已建立的 HTTPS 连接。
- 五类内置检测触发，正常 POST 样本无告警，导出 ZIP 的 SHA-256 校验通过。
- 测试前后 Nginx 配置哈希及 master/worker PID 一致。
- 实机确认半截 HTTPS 正文在停止和对端关闭时保存，客户端地址可关联。
- 实机验证磁盘预算超限后停止采集，探针缺失时重试一次并保留网卡采集。

## 性能状态

此前五分钟、三轮、四种模式对比尚未形成最终性能验收结论。

已完成的最终候选版本三轮完整检测与三轮 TLS 采集的 100 请求/秒结果如下。每组持续 300 秒。

| 模式 | 请求与响应配对 | 重复／串流 | 工具及子进程 CPU（单核） | 合计 RSS 峰值 |
| --- | --- | --- | --- | --- |
| 完整检测，第 1 轮 | 30000 / 30000 | 0 / 0 | 6.69% | 115.0 MiB |
| 完整检测，第 2 轮 | 30000 / 30000 | 0 / 0 | 6.63% | 112.5 MiB |
| 完整检测，第 3 轮 | 30000 / 30000 | 0 / 0 | 6.59% | 109.2 MiB |
| TLS 采集，第 1 轮 | 30000 / 30000 | 0 / 0 | 6.27% | 112.9 MiB |
| TLS 采集，第 2 轮 | 30000 / 30000 | 0 / 0 | 6.28% | 113.9 MiB |
| TLS 采集，第 3 轮 | 30000 / 30000 | 0 / 0 | 6.05% | 112.1 MiB |

这些组的请求错误率和已观测丢失计数均为 0。第三轮 TLS 采集与实机代码审核构建有时间重叠，主机总 CPU 指标受编译影响。表内 CPU 来自工具专用 cgroup，主机总体增量及延迟应在无并行构建的环境重新核对。cgroup 总内存统计还包括文件页缓存，峰值接近配置的 256 MiB 上限，不能用进程 RSS 代替它。

README 发布前审核还修复了证据写入错误处理、离线 PCAP 时间戳、SQLite 路径转义和时间排序，并升级部分传递依赖。这些修改已执行回归测试与静态检查，长期性能结果对应审核前的候选二进制，需要与最终提交区分。

## 验证边界

- 当前测试站响应体较小，性能数字适用于该工作负载。大正文、高带宽、多网卡和长期运行需要单独验证。
- eCapture 上游全套测试曾因现场缺少 MySQL 服务等环境依赖失败，已验证的 OpenSSL 与输出路径测试范围如上。
- 规则样本通过不代表覆盖所有攻击。部分消息、截断和加密协议覆盖范围需结合状态与证据判断。
- 现场原始 PCAP、数据库、Cookie 和正文未放入 Git 仓库。

## 仓库提交审核

审核修复了 TLS 事件持久化错误处理、WebSocket 取消监听的 goroutine 生命周期、队列槽位释放顺序、离线抓包时间戳、索引时间排序、特殊字符路径和导出错误处理。新增对应回归测试，验证脚本的目标主机和工具路径改为参数。

升级 SQLite 驱动、Protobuf 和传递依赖后，执行 Linux 竞态测试、静态检查和构建。最终依赖以 Go 1.26.11 构建，`govulncheck v1.9.0` 输出 `No vulnerabilities found.`。扫描结果反映执行时的漏洞数据库，SQLite 内嵌 C 代码和内核探针仍需各自的审查与测试。

## v0.1.2 便携发行包验证（2026-11-17）

构建候选提交 `75cd748` 的 [完整发行包验证](https://github.com/Sunmedalia/traffic/actions/runs/44041121589) 通过：

- Windows x64：原生竞态测试、静态检查；完整 ZIP 解压到含空格目录，在无 Npcap、无系统 Python 的环境运行 doctor、随包 Python/Frida 和两个探针的帮助。从其他工作目录启动 WinDivert 只读采集，回环 HTTP 的 4 次请求实际写入 SQLite，并由独立 traffic-console 读取状态。
- Ubuntu / CentOS 7：x64、ARM64 各自在干净发行版容器运行主程序、doctor、独立 console 和 eCapture，加载预加载库并保存 HTTP 采集会话；容器中不安装额外 libpcap 或编译器。主程序静态链接 libpcap，预加载库使用 glibc 2.17 基线。
- 实机 CentOS 7.9：glibc 2.17、原生 3.10.0-1160.119.1.el7.x86_64 内核。直接上传候选 tar.gz 解压，未编译或安装依赖；doctor、eCapture 帮助、LD_PRELOAD 加载通过。独立测试监听器接收 4 次回环 HTTP 请求，采集记录 72 个包、4 条事务，traffic-console 正常打开；使用 cgroup v1 资源预算，停止状态为 stopped。
- 本地 Go 全量竞态测试、分包内容回归测试、帮助分命令回归测试及工作流静态检查通过。

这组检查验证发行包的运行依赖、旧 glibc 兼容性和基本 HTTP 路径。未扩展为 Windows WinDivert 高负载完整性或旧内核 TLS 的正式验收。WinDivert 无每句柄队列丢弃计数，健康状态记录 drop_counter_unavailable；旧内核 TLS 的预加载要求仍适用。既有 Npcap 路径的历史验收不自动适用于 WinDivert。
