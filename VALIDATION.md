# 验证记录

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
