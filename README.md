# traffic

面向网站应急响应的流量采集与分析工具，提供 Linux ARM64 / x86_64 和 Windows x64 实验版本。独立采集程序保存 HTTP 请求、响应、检测依据和网络证据，分析程序通过中文 TUI、Web 界面或 JSON 命令实时查看及回看会话。

Linux 使用 libpcap、eCapture/eBPF、可选 Java Agent 和旧内核 OpenSSL 预加载后端。Windows 使用 Npcap 和可选 IIS / OpenSSL 动态探针。已验证环境中的探针可附加到运行中的服务，采集期间保持服务进程和网站配置。各后端的启动缺口、依赖及退出行为见下表和对应使用说明。

## 当前能力与验收范围

| 平台或服务 | 已实现能力 | 实机验证与边界 |
| --- | --- | --- |
| Linux ARM64 / x86_64 普通 HTTP | 按网卡、TCP 端口抓包，HTTP/1.1 请求响应重组，循环 PCAP | 支持 TCP 分段、乱序、重传、长连接、中文和分块正文 |
| Linux Nginx / OpenSSL | 运行中采集 HTTPS 明文、客户端端点和进程身份 | ARM64、x86_64 的 TLS 1.2/1.3 和采集前已建立连接通过 |
| Linux Apache | 自动发现 apache2/httpd，采集 OpenSSL HTTPS 明文 | ARM64 的 event、worker、prefork 已测，worker/prefork 已有阻塞读取存在首次漏采边界 |
| Linux Tomcat / JSSE | 显式动态附加 Java Agent，采集 HTTPS 明文 | ARM64 的 Tomcat 9/JDK 17、10.1/JDK 21 NIO Connector 已测，支持重复附加 |
| Linux 通用 OpenSSL | 指定 PID 采集 OpenSSL API 明文 | ARM64 的 HAProxy、外部 `SSL_read_ex` / `SSL_write_ex` 调用已测，其他程序及库版本需验证 |
| CentOS 7 x86_64 / OpenSSL 预加载 | 启动服务时加载 `LD_PRELOAD` 库，通过 Unix socket 获取明文 | 内核 3.10 / glibc 2.17 / OpenSSL 1.0.2k 的独立 HTTPS 服务已测，需启动时加载库 |
| Windows x64 / IIS 10 | Npcap HTTP 采集，显式启用 IIS 动态 HTTPS 明文后端 | Windows 10 LTSC 17763、HTTP/1.1、TLS 1.2 已测，存在启动漏采窗口和 Frida 运行时卸载限制 |
| Windows Nginx / Apache | 自动发现工作进程、Npcap HTTP、显式启用 OpenSSL HTTPS 明文采集 | Nginx 官方 1.28.0 x86、Apache 2.4.71 x64 的 TLS 1.2/1.3 正文比对通过，静态 Nginx 按二进制哈希适配 |
| Windows 通用 OpenSSL | 指定 PID，支持导出的 SSL_read/write 及 _ex API | 外部 _ex 调用的 TLS 1.2/1.3 已测，s_server 内置 BIO 路径未取得明文，自定义 BIO 目前适配 Apache |
| Linux / macOS / Windows 分析程序 | 中文 TUI、Web、JSON 查询，读取统一会话格式 | 支持会话选择、筛选、详情、状态查看和证据导出，可在分析机打开其他平台采集的完整会话 |

检测覆盖疑似 SQL 注入、命令注入、路径穿越、敏感文件探测和扫描，支持附加 YAML 规则、URL 多轮解码与有界 gzip 正文解码。记录包含命中片段、规则版本及解码来源，保留不完整和截断标记。

最新 IIS 验收在 24 次启动预热之后，完成 53 次 HTTP、54 次 HTTPS 请求响应正文比对，覆盖中文、分块、文件响应、四路并发、长连接、大正文截断和五类规则。预热请求记录到 14 次，漏采 10 次。随后 107 次请求均通过，已有 HTTPS 连接继续复用，配置哈希和工作进程身份检查通过。全部 121 条记录和导出证据可用，启动漏采需要单独评估。各平台测试环境和完整验收数据见 [验证记录](VALIDATION.md)。

## 程序职责

| 程序 | 源码入口 | 功能 |
| --- | --- | --- |
| `traffic` | `cmd/traffic` | `doctor` 检查采集环境，`capture` 实时采集，`import` 将已有 PCAP 转为会话，`rules check` 校验采集规则 |
| `traffic-tui` | `cmd/traffic-tui` | 默认打开中文 TUI，分析会话中的请求、响应和告警，`web` 启动浏览器界面，提供 `status`、`requests`、`events`、`show`、`export` 查询及证据导出命令 |

采集程序负责网卡抓包、TLS 探针、协议还原、规则初筛、会话写入和资源管理。分析程序读取会话索引及证据，提供筛选、详情浏览和导出。两者通过版本化的 SQLite、JSON 和 PCAP 会话文件交换数据，可分别启动和部署。`internal/session` 定义共享的数据结构、数据库布局和正文解码逻辑。

升级时将原来的 `traffic tui` 改为 `traffic-tui`，将 `traffic status/requests/events/show/export` 的程序名改为 `traffic-tui`。原来的 `traffic analyze` 改名为 `traffic import`，用于把离线 PCAP 还原并写入新会话。

## 能力

- 捕获选定网卡和 TCP 端口的原始流量，以循环 PCAP 保留证据。
- 还原 HTTP/1.1 请求与响应，处理 TCP 分段、乱序、重传、长连接和分片正文。
- 获取 HTTPS 明文，Linux 支持 Nginx、Apache、通用 OpenSSL 和显式启用的 Tomcat JSSE 后端，Windows 支持显式启用的 IIS HTTP Server API 和 OpenSSL 后端。TLS 版本和已有连接覆盖以各平台验收结果为准。
- 检测疑似 SQL 注入、命令注入、路径穿越、敏感文件探测和扫描行为，显示匹配片段及解码来源。
- 通过中文 TUI、Web 和 JSON 命令查询全部请求或告警，按客户端、规则、级别、服务和时间筛选，TUI/Web 另支持 Host/URL 关键词。
- 导出请求、响应、关联 PCAP 和 SHA-256 校验清单，支持采集结束后的证据核对。
- 提供正文大小、队列、磁盘及保留期限制，Linux 使用 cgroup v2、Windows 使用 Job Object，状态中报告资源约束、丢弃、截断和采集问题。

## 构建

构建需要 Go 1.26.7+、CGO 和 C 编译器。Linux 采集程序依赖 libpcap，Windows 采集程序依赖 Npcap。分析程序使用 Go 读取 PCAP、通过 CGO SQLite 驱动读取会话索引。以下为 Linux 的 Debian/Ubuntu 构建流程。

```bash
sudo apt-get update
sudo apt-get install -y build-essential libpcap-dev git

git clone https://github.com/Sunmedalia/traffic.git
cd traffic
./scripts/build-linux.sh
./bin/traffic doctor
```

构建脚本执行竞态测试、`go vet`，生成独立的 `bin/traffic`、`bin/traffic-tui` 和校验文件。普通 HTTP 采集可通过 `--no-tls` 启动。

也可以分别构建两个程序。

```bash
go build -o bin/traffic ./cmd/traffic
go build -o bin/traffic-tui ./cmd/traffic-tui
```

分析程序可在 Linux、macOS 或 Windows 上构建。macOS 主要用于分析已有会话，Linux eBPF 和 Windows IIS 采集后端分别运行在对应目标系统。Windows 构建命令见下文。

### Linux HTTPS 采集依赖

HTTPS 路径使用固定版本 eCapture 加本项目补丁。当前构建脚本按 Linux 主机架构生成 **ARM64 或 x86_64 / OpenSSL 3.0、3.5 / CO-RE** 探针，并包含自定义 BIO 的 socket 关联以及 `SSL_read_ex`、`SSL_write_ex` 支持。其他版本需要单独验证。

```bash
# 另外需要 Go 1.26+，以及上游 eCapture 所需构建环境
sudo apt-get install -y clang llvm bpftool libelf-dev libssl-dev flex bison make file pkg-config
./scripts/build-ecapture.sh /tmp/traffic-ecapture-build
```

构建目录必须不存在。脚本检出上游提交 `143e771cf2b4919aedc27fd7b4b24ff87b8725b9`，应用补丁并生成 `bin/ecapture`、许可证和校验文件。构建细节见 [eCapture 构建文档](https://github.com/gojue/ecapture/blob/v2.9.1/docs/agent/build-test.md)。

补丁修复实机发现的连接缓存崩溃和 FD 复用时的元数据竞争，并减少解码复制。socket 地址及 inode 身份与对应明文一起进入事件。多核机器上的 TLS 事件使用 100 毫秒时间排序窗口，空闲时也会刷新末批事件。补丁扩展了内部 eBPF ABI，需要配套构建探针字节码与用户态解码器。[补丁文件](patches/ecapture-v2.9.1-connection-cache.patch)


### CentOS 7 / 旧内核的 OpenSSL 明文采集

新增 Linux `LD_PRELOAD` 后端，适用于可在启动时加载动态库的 OpenSSL 服务。采集库在 `SSL_read`、`SSL_write` 及对应 `_ex` API 返回后复制实际消费或产生的明文，通过有界异步队列发送至本地 Unix socket，采集器复用 HTTP 还原、检测和证据存储。该路径可在内核 3.10 上运行。

在目标系统构建，以匹配 glibc 和 libpcap。CentOS 7 需要 GCC、glibc-devel、libpcap-devel、Python 3 和项目 `go.mod` 指定版本的 Go。原生编译该库需要 libc 头文件，无需 OpenSSL 开发头文件。

```bash
go build -o bin/traffic ./cmd/traffic
go build -o bin/traffic-tui ./cmd/traffic-tui
bash scripts/build-openssl-preload.sh

# 自动创建独立的回环 HTTPS 服务并完成测试，输出目录必须不存在
sudo python3 scripts/linux/verify-preload.py \
  --binary "$PWD/bin/traffic" --analysis-binary "$PWD/bin/traffic-tui" \
  --library "$PWD/bin/libtraffic-openssl.so" --output /opt/traffic-preload-test
```

手动使用时先启动采集器，等待状态为 `listening-preload`，再以目标服务的启动命令加载采集库。

```bash
sudo ./bin/traffic capture --interfaces lo --ports 8443 \
  --openssl-preload-socket /run/traffic-plaintext.sock --output ./sessions/old-kernel

# 在另一个终端启动独立的测试服务，替换末尾为实际启动命令
sudo env LD_PRELOAD="$PWD/bin/libtraffic-openssl.so" \
  TRAFFIC_OPENSSL_SOCKET=/run/traffic-plaintext.sock /path/to/test-service
```

socket 为 `0600`，发送进程需要与采集器同 UID，并具有父目录访问权限。采集器校验 Unix socket 内核凭据与 `/proc` 进程启动标识，成功接收后状态为 `active-preload`，事务后端为 `openssl-preload`，原始事件写入 `tls/openssl-preload.jsonl`。`--ports` 继续筛选端口，此模式使用 `auto` 服务且不指定 `--pid`。加载该库的服务需要重新启动，库随服务进程退出而卸载。

队列最多 128 条事件，单条最多约 19 KiB，发送线程遇到背压进行有界重试。可上报的传输缺口计入 `tls_dropped`，进程崩溃、`_exit`、采集器停机及最后无法送出的事件仍可能形成未知缺口。采集完整性保持 `unverified`。CentOS 7 的 cgroup v1 环境下，现有 cgroup v2 资源限制报告 `unavailable`。

该后端目前验证动态 OpenSSL 1.0.2k / HTTP/1.1 / TLS 1.2。静态链接、绕过符号拦截的加载方式、自定义无 socket BIO、Go TLS、HTTP/2、其他 OpenSSL 版本及长期性能需要另行适配或验证。Nginx、Apache 等中间件需要分别实测。

### Windows 构建与 HTTP 采集

Windows x64 构建需要 Go 1.26.7+、x64 MinGW GCC，以及用于运行采集和抓包测试的 [Npcap](https://npcap.com/)。在 PowerShell 中执行以下命令。

```powershell
powershell -ExecutionPolicy Bypass -File scripts/windows/build.ps1
.\bin\windows\traffic.exe doctor
.\bin\windows\traffic.exe capture --no-tls --ports 8080,8443 --duration 60s --name windows-http
.\bin\windows\traffic-tui.exe
```

默认枚举具有地址的可用适配器及回环接口，跳过标记为断开的设备。也可使用 `doctor` 返回的完整 Npcap 设备名，例如 `--interfaces '\Device\NPF_Loopback'`。Windows 抓包快照上限为 256 KiB，避免回环帧超过 65,535 字节导致尾部丢失。PCAP 文件名使用设备名的 SHA-256，原始设备名保留在请求来源中。证据目录使用继承 ACL，授权当前用户、SYSTEM 和 Administrators。采集器使用 Job Object 限制合计 256 MiB 内存及单核 50% CPU，生效情况写入状态文件。

### Windows IIS HTTPS 与测试站点

以下脚本为专用实验机安装 IIS、ASP.NET，并创建独立的 `TrafficLab` 站点、应用池、自签证书和防火墙规则，监听 HTTP 8080、HTTPS 8443。已有目录、同名站点或端口冲突会报错。安装组件可能要求首次重启，脚本会保留安装记录，重启后通过 `-Resume` 继续。

```powershell
powershell -ExecutionPolicy Bypass -File scripts/windows/setup-iis.ps1
# 仅在首次安装要求重启且已完成重启后执行
powershell -ExecutionPolicy Bypass -File scripts/windows/setup-iis.ps1 -Resume
# 先验证 HTTP 采集与站点 HTTPS 访问，完整 HTTPS 明文验证见下方 --iis-probe 示例
python scripts/windows/verify-iis.py --binary .\bin\windows\traffic.exe --analysis-binary .\bin\windows\traffic-tui.exe --output C:\traffic-iis-verification
```

验收脚本发送 HTTP/1.1 请求，检查中文正文、分块、长连接、并发、大小限制、规则、配置哈希、工作进程身份及导出校验。报告记录 HTTPS 明文、启动预热漏采、卸载确认和已有连接复用。未显式启用 IIS 探针时，Windows TLS 状态报告 `unavailable`，HTTPS 网络包保存为密文。`--service iis` 根据 IIS 配置关联候选服务端口，HTTP.sys 监听端口不能直接确定具体站点或应用池。

IIS HTTPS 探针通过固定版本 Frida 17.5.1 动态附加运行中的 x64 `w3wp.exe`，在 HTTP Server API 收发边界复制明文，通过 I/O 完成关联处理异步接收，无需安装 IIS 模块或回收应用池。需安装 Python 和 Frida，并显式指定辅助脚本及临时目录。`setup-iis.ps1` 为 `TrafficLab` 应用池创建专用可读的 `C:\traffic-lab\probe-runtime`，证据目录保持独立权限。其他应用池需要对应身份可读取探针临时目录。

```powershell
python -m pip install frida==17.5.1
.\bin\windows\traffic.exe capture --service iis --ports 8080,8443 --iis-probe .\scripts\windows\probe-iis.py --iis-runtime-dir C:\traffic-lab\probe-runtime --duration 60s
python scripts/windows/verify-iis.py --binary .\bin\windows\traffic.exe --analysis-binary .\bin\windows\traffic-tui.exe --iis-probe .\scripts\windows\probe-iis.py --output C:\traffic-iis-https-verification
```

辅助脚本、`iis-plaintext.js` 和 `probe-iis.js` 应放在同一目录，`--iis-python` 可指定装有 Frida 的 Python。原始 API 事件保存在会话 `tls/iis-*.jsonl`，诊断在 `logs/iis-*.log`，请求记录的 backend 为 `iis-httpapi`。正文和头部按 HTTP/1.1 重建，原始 API 事件及 PCAP 保留供复核。内存队列、正文复制和磁盘均有边界，丢弃及不完整记录显式报告。

Windows 10 17763 的已测范围为 HTTP/1.1、TLS 1.2 及同一个 IIS 工作进程。启动窗口、其他协议、内核缓存和进程替换的边界见下文。缓存片段等无法复制的实体类型会标记缺口。

停止时逐个核对拦截位置原指令已恢复，报告中 `hooks_removed` 表示该检查结果。未完成 I/O 可能使 Frida 脚本卸载或传输断开等待，辅助进程会有界退出，Frida 运行时可能仍留在工作进程。完整运行时卸载尚未验收，报告另外记录 `script_unloaded` 和 `transport_detached`。

#### IIS 启动提示与完整性判断

```text
IIS dynamic attach cannot recover receive calls posted before attachment; startup requests may be missed
```

当前实现每次收到探针 `ready` 事件后，都会将这条能力限制写入 `status.json` 的 `errors`，TUI/Web 的问题列表会展示它。IIS 已提前投递的异步接收调用没有经过新附加探针的入口，探针无法恢复这些调用的缓冲区参数，因此采集启动后到达的首批请求可能漏采。随后新投递的接收调用可以正常关联。

`tls=attached` 表示探针安装成功，完整性仍需结合客户端请求数、保存记录、`incomplete`、`truncated` 和各类丢弃计数判断。启动及其他探针盲区的实际漏采数仍为未知，`tls_dropped` 仅记录已观测丢弃下限。状态显式保留 `tls_coverage=unverified` 和 `tls_missing_estimate=null`，TUI、Web 与导出证据均提示完整性未验证。10 条为当前测试机的实测值，预热次数需要结合环境验证。

仅观察调用元数据时可运行以下命令。

```powershell
python scripts/windows/probe-iis.py --pid 1234 --duration 30 --runtime-dir C:\traffic-lab\probe-runtime --out C:\traffic-iis-api.jsonl
```

`scripts/windows/restore-iis.ps1` 移除实验站点、应用池、证书和防火墙规则，保留文件与安装记录。需要同时卸载本次新增的 IIS 组件时使用 `-RemoveInstalledFeatures`，Windows 可能再次要求重启。恢复脚本应在测试结束后运行。

## Windows Nginx、Apache 与通用 OpenSSL

Windows 采集器识别 `nginx.exe`、`httpd.exe`、`apache.exe` 和 `apache2.exe`，从 Windows TCP 表读取监听端口，关联 master/worker 并选择工作进程。普通 HTTP 使用 Npcap，HTTPS 明文通过 Frida 17.5.1 动态附加 OpenSSL 调用。支持 `SSL_read`、`SSL_write`、`SSL_read_ex` 和 `SSL_write_ex`，以实际成功读写长度复制有界数据。Apache mod_ssl 的自定义 BIO 通过 OpenSSL app_data、Apache 和 APR 公共 API 取得套接字端点。

```powershell
# 在管理员终端运行，端口按已有站点设置
python -m pip install frida==17.5.1
.\bin\windows\traffic.exe doctor --service auto
.\bin\windows\traffic.exe capture --service nginx --ports 80,443 --openssl-probe .\scripts\windows\probe-openssl.py --probe-runtime-dir C:\traffic-lab\probe-runtime --duration 60s
.\bin\windows\traffic.exe capture --service apache --ports 80,443 --openssl-probe .\scripts\windows\probe-openssl.py --probe-runtime-dir C:\traffic-lab\probe-runtime --duration 60s

# 同一会话采集已运行的 IIS、Nginx、Apache
.\bin\windows\traffic.exe capture --service auto --ports 80,443,8080,8443 --iis-probe .\scripts\windows\probe-iis.py --openssl-probe .\scripts\windows\probe-openssl.py --probe-runtime-dir C:\traffic-lab\probe-runtime

# 其他使用 OpenSSL DLL 的进程，必要时指定模块名
.\bin\windows\traffic.exe capture --service openssl --pid 1234 --ports 9443 --libssl libssl-3-x64.dll --openssl-probe .\scripts\windows\probe-openssl.py --probe-runtime-dir C:\traffic-lab\probe-runtime
```

`--probe-python` 指定安装了 Frida 的 Python，兼容原有 `--iis-python`。`--probe-runtime-dir` 与 `--iis-runtime-dir` 等价，该目录需预先存在并允许目标进程身份读取。辅助脚本目录中需同时保留 `probe-openssl.py`、`probe-iis.py`、`openssl-plaintext.js` 和 `openssl-profiles.json`。OpenSSL 原始事件写入 `tls/openssl-*.jsonl`，诊断写入 `logs/openssl-*.log`，统一请求记录的 backend 为 `openssl`。进程启动时间参与身份校验，发现进程替换后为新身份建立采集后端。

OpenSSL DLL 优先按导出函数解析。官方 Windows Nginx 静态链接 OpenSSL，内置 profile 对应 nginx.org 的 `nginx-1.28.0.zip` 中 x86 `nginx.exe`，先校验整个文件的 SHA-256，再校验函数入口字节和 RVA。其他静态版本需通过 `--openssl-profile FILE.json` 提供匹配 profile，格式见内置文件。无匹配后端时目标报告 `unavailable`，网卡采集继续运行。不能把一个版本的函数位置套用于另一二进制。

动态附加只覆盖附加后进入的调用，附加前已进入的阻塞读取及半截消息可能漏采。首次仅观察到的响应会被丢弃，避免配给后续长连接请求。队列丢失后切断请求响应关联，并为后续记录保留不完整标记。停止时核对原始指令恢复结果，另记录脚本卸载和传输断开状态。Nginx / Apache 的本次运行中两项卸载均成功，IIS 的未完成 I/O 卸载边界仍见上文。

实机测试使用独立站点并通过回环地址访问，Nginx 端口为 18080/18443，Apache 为 18081/18444，反向代理到 `middleware-fixture.py` 的 18090。`verify-middleware.py` 在保持已有连接活跃的预热后，检查 HTTP/1.1、TLS 1.2/1.3、中文 POST、分块、HEAD、404、并发、大正文截断、规则告警、工作进程身份、配置哈希及卸载报告。

```powershell
python scripts/windows/verify-middleware.py --binary .\bin\windows\traffic.exe --probe .\scripts\windows\probe-openssl.py --config C:\path\to\nginx.conf --config C:\path\to\httpd.conf --output C:\traffic-middleware-verification
```

最终 62 条验收请求全部通过，包括 12 条 HTTP 和 50 条 HTTPS，覆盖 TLS 1.2/1.3。会话另包含 10 条预热记录，共 72 条记录、1163 个包和 6 次告警，三类已观测丢弃计数均为零。两个服务的工作进程身份及配置哈希检查通过，探针原始指令、脚本卸载和传输断开均确认成功。外部 `SSL_read_ex` / `SSL_write_ex` 的通用 PID 采集另外通过 TLS 1.2/1.3 两条请求。OpenSSL `s_server -www` 的内部 BIO 路径本次未取得明文，其他中间件仍需单独验证。HTTP/2、HTTP/3、Go TLS、Windows JSSE、其他自定义 BIO、其他静态 Nginx 版本及长期性能尚未验收。

## Linux 快速使用

在目标 Linux 主机执行，使用 `doctor` 确认接口、权限、内核 BTF 和各服务加载的 TLS 库。

```bash
./bin/traffic doctor

sudo ./bin/traffic capture \
  --interfaces eth0 \
  --ports 80,443 \
  --ecapture "$PWD/bin/ecapture" \
  --libssl /lib/aarch64-linux-gnu/libssl.so.3 \
  --output ./sessions/incident-001
```

x86_64 主机可将示例中的库路径改为 `/usr/lib/x86_64-linux-gnu/libssl.so.3`，或省略 `--libssl` 自动发现。构建得到的三个可执行文件须使用同一目标架构。

将 `eth0` 替换为目标主机的实际接口。`--libssl` 可省略，程序从目标进程映射发现动态库。默认接口为 Linux `any`，包含回环接口。`--ports` 限定抓包和 TLS 明文事件的本地端口。探针按动态库和 UID 分组，随后按选定进程及启动时间过滤，root 目标使用 PID 限定。多站点共用进程和端口时，采集包含这些站点的请求。

采集时输出 JSON 告警。`Ctrl+C` 停止采集、卸载探针并保存摘要。每次采集使用新的会话目录。

```bash
# 采集过程中也可查询
./bin/traffic-tui status --session ./sessions/incident-001
./bin/traffic-tui events --session ./sessions/incident-001
./bin/traffic-tui requests --client 192.0.2.10 --session ./sessions/incident-001

# 查看完整记录，EVENT_ID 来自列表结果
./bin/traffic-tui show EVENT_ID --session ./sessions/incident-001

# 停止采集后导出，目标文件必须不存在
./bin/traffic-tui export EVENT_ID \
  --session ./sessions/incident-001 \
  --out ./evidence.zip
```

列表返回 JSON 摘要，`show` 包含可读正文及 base64 字节字段。保存的 HTTP 文本由解析器重新序列化，原始网络字节保留在 PCAP 中。可按 `--since`（RFC3339）、`--client`、`--rule`、`--severity` 和 `--limit` 查询。

```bash
# 60 秒普通抓包与 HTTP 分析
sudo ./bin/traffic capture --no-tls --duration 60s --output ./sessions/http-001

# 将已有明文 HTTP PCAP 导入会话
./bin/traffic import capture.pcap --ports 80,8080 --output ./sessions/offline-001

# 查看所有选项
./bin/traffic capture --help
```

## Linux Apache、Tomcat 和其他 OpenSSL 服务

`--service` 默认 `auto`，发现 Nginx worker、Apache 的 `apache2/httpd` 及独立 Tomcat。`--pid` 限定进程探针，`--ports` 默认仍为 `80,443`。网卡抓包始终按接口和端口过滤，明文 HTTP 的服务归属根据本机监听端口推断。服务发现每两秒更新，工作进程变化与新探针挂载之间可能存在采集窗口。`doctor` 的 `tls_verified: false` 表示环境检查尚未证明能取得明文，真实请求验证结果见验证记录。

```bash
sudo ./bin/traffic capture --service apache --ports 8081,8444
sudo ./bin/traffic capture --service tomcat --ports 8080 --no-tls
sudo ./bin/traffic capture --service openssl --pid 1234 --ports 9443
```

通用 OpenSSL 服务需要指定 PID，已使用 HAProxy 验证。采集记录包含服务、目标标识、后端和本地端点。目标标识使用 PID 与进程启动时间，明文 HTTP 的服务归属根据本地监听端口确定，多个进程共享端口时保留服务类型。代理链路按每一跳分别记录。

Tomcat JSSE HTTPS 通过显式启用 Java Agent 采集，首批支持 Tomcat 9/JDK 17、Tomcat 10.1/JDK 21 的 NIO Connector。OpenSSL 后端优先使用外部探针。

```bash
# 使用 JDK 17+ 和 Maven 构建，JAR 包含固定版本且重定位的 Byte Buddy
./scripts/build-java-agent.sh

sudo ./bin/traffic capture --service tomcat --pid 1234 \
  --ports 8080,8443 --java-attach \
  --java-agent "$PWD/bin/traffic-java-agent.jar"

# 同一会话采集多个服务，仅对指定 JVM 启用 Java Agent
sudo ./bin/traffic capture --service auto --ports 80,443,8081,8444,8083,8446 \
  --java-attach --java-pid 1234 --java-agent "$PWD/bin/traffic-java-agent.jar"
```

目标 JVM 需要支持动态附加。附加助手默认使用目标 Java，可通过 `--java-helper /path/to/jdk/bin/java` 指定具有 `jdk.attach` 模块的匹配 JDK。工具以目标 UID/GID 运行附加助手，通过带随机令牌和版本校验的回环通道传输数据，临时文件在结束后清理。JDK 21 可能输出动态加载 Agent 的提示。禁止附加的 JVM 会报告失败，采集器继续保留网络包。

Java 探针使用一条发送线程和 128 个分片槽位，单片上限 64 KiB，队列正文最多 8 MiB。业务线程只进行有界复制和非阻塞入队，溢出后标记数据缺口。JVM 内探针开销由业务 JVM 承担，采集程序的 cgroup 约束覆盖采集器与附加助手。停止后通道关闭，Agent 停用并恢复字节码，已加载的类随 JVM 保留，同一 JVM 可再次附加；Agent 本身暂不支持在同一 JVM 内热升级。

TUI 概览显示各服务的探针状态，详情展示服务、目标、后端与本地端点。筛选面板支持服务条件，也可使用以下查询。

```bash
./bin/traffic-tui requests --session SESSION --service apache
```

Apache worker/prefork 在启动采集前已经阻塞于 `SSL_read` 的调用，其首次返回可能漏采，后续调用和新连接可采集。OpenSSL 3.0 内置 `s_server -www` 的 BIO 路径实测尚未取得明文，外部 `SSL_read_ex`/`SSL_write_ex` 调用已验证。

普通访问验收脚本 `scripts/verify-services.py` 针对已经运行的实验服务发送六次串行请求，检查已有 HTTPS 连接、中文 POST、响应关联、配置哈希、原有进程身份及丢弃计数。脚本需要显式指定实验配置路径、端口和探针路径。`--new-connections-only` 显式跳过已有连接测试，并在报告中记录。

## 会话目录

省略 `--output` 时，采集和 PCAP 导入会自动按主机、日期和本地开始时间创建会话。使用 `--name` 标注网站或事件，默认名称分别为 `capture` 和 `import`。

```bash
sudo ./bin/traffic capture --name nginx
sudo ./bin/traffic capture --data-dir /var/lib/traffic/sessions --name incident-001
./bin/traffic import capture.pcap --name offline-review
```

例如在主机 `web-01` 上执行第一条命令，将生成以下目录。

```text
sessions/web-01/2026-11-11/15-04-05-nginx/
├── manifest.json
├── status.json
├── index.sqlite
├── capture.lock
├── packets/
│   └── any-01.pcap
├── tls/
│   └── events.jsonl
└── logs/
    └── tls.log
```

`packets/` 保存循环 PCAP，`tls/` 保存 TLS 原始明文事件，`logs/` 保存探针诊断。TLS 相关目录按需创建。SQLite 运行期间还可能产生 `index.sqlite-wal` 和 `index.sqlite-shm`。复制会话时应完整复制整个目录。

启动时程序在 stderr 输出会话绝对路径，可将此路径传给 `traffic-tui --session`。`manifest.json` 记录主机、会话名称、采集或导入模式、开始时间、过滤条件和目录布局版本。新目录使用布局版本 2，HTTP 数据结构继续使用 schema version 1，分析程序支持原有平铺目录和新目录的读取及证据导出。

同一秒内启动同名会话时，目录自动添加 `-02`、`-03` 等后缀。`--name` 支持中文、字母、数字、连字符、下划线和点，最大 80 字节。`--output` 继续表示精确的会话路径，适用于已有脚本。它与显式设置的 `--data-dir` 互斥。

## 终端交互界面

使用独立的分析程序，在交互式终端打开正在采集或已经结束的会话。

```bash
# 无参数启动，在界面选择会话
./bin/traffic-tui

# 从其他采集根目录选择会话
./bin/traffic-tui --data-dir /var/lib/traffic/sessions

# 直接打开指定会话
./bin/traffic-tui --session ./sessions/incident-001

# 每两秒刷新，并预设筛选条件
./bin/traffic-tui --session ./sessions/incident-001 \
  --refresh 2s --client 192.0.2.10 --severity high
```

无参数启动会递归扫描当前工作目录及程序所在目录对应的 `sessions/`，按开始时间从新到旧列出会话。在会话目录内启动也会识别当前会话。选择页显示会话名称、时间、状态、请求数、告警数和完整路径，兼容旧版平铺目录与新版分层目录。程序通过 `index.sqlite` 及请求表结构识别会话，损坏的索引会标记为不可用。请求数和告警数来自采集状态文件，缺失时显示未知。

选择页使用 `↑` / `↓`、`j` / `k` 选择，`Enter` 打开，`r` 重新扫描，`o` 输入其他采集根目录、会话目录或 `index.sqlite` 文件路径。进入分析页后按 `s` 返回会话选择页。仅含 PCAP 或 HTTP 文本的导出目录需要先导入或找到对应的完整会话。

中文界面提供采集概览、请求列表和告警列表。概览显示累计请求和告警命中、网络包、各类丢弃、TLS 状态、资源限制及采集错误。列表每页 100 条，支持按客户端、规则、严重程度、起始时间和 Host/URL 关键词组合筛选。起始时间使用 RFC3339，例如 `2026-11-11T10:00:00+08:00`。规则和严重程度组合筛选要求同一条告警同时匹配。

| 按键 | 操作 |
| --- | --- |
| `1` / `2` / `3` | 切换概览、请求、告警 |
| `s` | 返回会话选择页 |
| `↑` / `↓` 或 `j` / `k` | 选择请求或滚动详情 |
| `g` / `G` | 列表首尾 |
| `n` / `p`、`←` / `→`、`PgDn` / `PgUp` | 列表翻页 |
| `Enter` | 打开请求详情 |
| `Tab` / `Shift+Tab` | 切换请求、响应、解码正文、检测依据 |
| `/` | 打开筛选面板，`Tab` 切换字段，`Enter` 应用，`Ctrl+R` 清空字段 |
| 空格 / `r` | 暂停或恢复自动刷新 / 手动刷新 |
| `Esc` | 返回列表或取消筛选 |
| `?` | 打开快捷键帮助 |
| `q` / `Ctrl+C` | 退出 TUI |

默认每秒自动刷新，历史页保持当前浏览位置，打开的详情会更新后续到达的响应。暂停刷新后仍可手动刷新和查询。宽度达到 120 列时详情与列表分栏，窄终端使用独立详情页。建议至少 80 列、24 行，时间按界面标注的本地时区显示。

详情显示保存的请求响应文本、可用的 gzip 请求正文解码结果，以及规则版本、命中片段和解码来源。不完整及截断记录在列表和详情中标注。采集心跳超过五秒未更新时提示心跳过期，状态文件缺失时仍可浏览 SQLite 中的请求。分析程序以只读方式打开现有 SQLite 索引，证据导出写入指定的新 ZIP 文件。运行用户需要会话目录和文件的读取权限，普通查询和界面浏览无需管理员权限。

## Web 界面

`traffic-tui web` 在同一个分析程序内启动浏览器界面，读取方式、筛选条件和证据导出与 TUI 一致，页面资源内嵌在可执行文件中。

```bash
# 扫描默认的 sessions/ 目录
./bin/traffic-tui web

# 指定采集根目录、单个会话或监听地址
./bin/traffic-tui web --data-dir /var/lib/traffic/sessions
./bin/traffic-tui web --session ./sessions/incident-001 --listen 127.0.0.1:9000 --refresh 2s
```

启动后在 stderr 输出带本次运行访问令牌的地址，例如 `http://127.0.0.1:8080/#token=…`，在浏览器打开即可。令牌位于 URL 片段，浏览器不会把它发送给服务端，页面将其保存在当前标签页的 sessionStorage，并通过 `Authorization` 头向接口发送令牌。新标签页可再次打开完整启动地址或输入令牌。每次启动生成新令牌，也可通过环境变量 `TRAFFIC_WEB_TOKEN` 指定至少 16 个字符的固定令牌。

Windows 在 PowerShell 中也可以启动 Web 界面，默认端口为 8080。与同机 IIS 测试站点同时运行时，可将分析界面设为 9000。

```powershell
.\bin\windows\traffic-tui.exe web --data-dir C:\traffic-lab\validation --listen 127.0.0.1:9000
```

默认只监听回环地址，连接为明文 HTTP。分析远程主机上的会话时建议使用 SSH 端口转发。

```bash
ssh -L 8080:127.0.0.1:8080 user@web-01
```

监听非回环地址需要显式添加 `--allow-remote`，此时令牌、请求正文、Cookie 和认证信息会以明文经过网络，仅适用于受信任的隔离网络。

页面包含会话选择、采集概览、请求列表和告警列表。列表每页 100 条并按 `--refresh` 间隔自动刷新，默认每秒一次，最小 500 毫秒，历史页保持当前浏览位置。筛选支持客户端、Host/URL 关键词、规则、级别、服务和起始时间。详情显示请求、响应、gzip 解码正文和检测依据，“导出证据”下载与 `traffic-tui export` 相同的 ZIP，采集进行中时导出会被拒绝。可用快捷键为 `1` / `2` / `3` 切换标签，`j` / `k` 或 `↑` / `↓` 选择请求，`n` / `p` 翻页，`/` 聚焦筛选，`Esc` 关闭详情。

Web 服务以只读方式打开 SQLite 索引，会话标识只能解析到启动时指定目录下发现的会话。采集内容来自不可信来源，页面以纯文本渲染所有字段，并通过内容安全策略限制为仅加载内嵌资源。

## 检测规则

内置规则对原始内容和最多两轮 URL 解码视图匹配。gzip 正文有界解码，告警记录命中视图、片段、规则版本和解码轮次。告警表示疑似攻击，判断攻击结果需要结合响应和其他现场证据。

扫描默认按来源 IP 聚合，60 秒内至少访问 20 个不同路径，且至少一半响应为 404。通过 `--scan-window` 和 `--scan-paths` 调整。

附加规则使用 YAML 列表，正则为 Go RE2 语法。

```yaml
- id: CUSTOM-001
  version: 1
  severity: medium
  field: url
  pattern: '(?i)/suspicious-endpoint'
```

```bash
./bin/traffic rules check rules.yaml
sudo ./bin/traffic capture --rules rules.yaml --no-tls --output ./sessions/custom-001
```

`field` 支持 `url`、`request`、`response`、`request.headers`、`response.headers`、`request.body`、`response.body`。单个头部使用 `request.header.User-Agent`、`response.header.Set-Cookie` 等字段名，HTTP 头部名大小写不敏感，重复头部值以换行连接。头部和正文选择器按各自字段匹配，gzip 正文在有界解压后追加检测，响应到达时重新检测并输出新增告警。`severity` 支持 `low`、`medium`、`high`，`--no-detect` 关闭攻击检测。

内置规则新增 XSS、SSRF、XXE、SSTI、JNDI、常见序列化载荷、Webshell 上传及访问路径，以及响应中的 passwd / 命令输出特征。这些规则覆盖常见特征，混淆变体和业务语境仍需结合原始流量判断。响应特征作为疑似成功证据保留，接口合法返回同类文本也可能命中。

### 可信代理与来源地址

使用 `--trusted-proxies 10.0.0.0/8,192.0.2.10,2001:db8::/32` 指定可信代理的 IP 或 CIDR。直连对端在列表中时，解析 `X-Forwarded-For`，从右向左寻找第一个非可信地址。缺少该头部时使用单值 `X-Real-IP`。非法或空链保留直连身份。默认列表为空。

索引、告警和扫描聚合使用解析后的 `client`，`peer_client` 保留实际直连端点，`client_source` 记录所用头部。代理转发头不含原始端口，解析后的端口记为 `0`。TUI / Web 详情显示地址依据，PCAP 导出按直连端点筛选。

### 告警外送

`--alert-webhook https://siem.example/traffic` 将每条新增告警的 JSON 异步 POST 至接收端。可通过环境变量 `TRAFFIC_WEBHOOK_TOKEN` 发送 Bearer 令牌，正文包含记录 ID、时间、URL、来源地址、直连端点和检测依据。接收端可使用 `Idempotency-Key` 去重。

单次请求超时 3 秒，网络失败、HTTP 429 和 5xx 最多尝试三次，重定向计为失败。有界队列最多 128 条、4 MiB，退出时等待最多 5 秒，然后取消剩余请求。`status.json`、TUI 和 Web 分别显示 `alert_delivered`、`alert_delivery_failed`、`alert_delivery_dropped`。队列位于内存，失败和溢出后的告警仍可从会话索引读取，重启后需由外部集成补送。

## 证据与资源

| 项目 | 默认行为 |
| --- | --- |
| 请求与响应正文 | 分别保留 256 KiB、64 KiB，超出标记截断 |
| 正文上限配置 | `--request-limit`、`--response-limit`，单位字节，最大 1 MiB |
| HTTP 头部 | 解析上限 32 KiB |
| PCAP | 每接口 64 MiB 分段、16 段循环 |
| 会话磁盘预算 | 2 GiB，`--disk-limit-mib` 调整，达到上限停止采集 |
| 低磁盘空间 | 可用空间不足 512 MiB 时停止采集 |
| 索引保留期 | 24 小时，`--retention` 调整，删除后数据库空间可供后续写入复用 |
| 进程资源 | Linux cgroup v2 / Windows Job Object，可用时限制工具及子进程合计 256 MiB 内存、单核 50% CPU。目标服务内的探针开销由目标进程承担 |
| 文件权限 | Linux/macOS 会话目录 `0700`、证据文件 `0600`。Windows 通过继承 ACL 授权当前用户、SYSTEM 和 Administrators |

队列有界。`status.json` 记录网卡丢包、用户态队列丢弃、TLS 已知丢弃、错误和资源限制是否生效。Linux OpenSSL 探针失败后最多重试一次。Java/IIS/Windows OpenSSL 后端失败时报告不可用并保留网卡采集，进程探针的队列缺口和未完成消息保留完整性标记。IIS 后端在采集结束时保存尚未完成的已识别请求。


`tls_wire_records` 统计 TCP 重组后完整可读的 TLS 外层记录，`tls_requests` 统计已保存的 TLS 明文请求。两者用于排查覆盖差异。TLS 1.3 外层记录包含加密握手，一条 HTTP 请求可跨多个 TLS 记录，同一连接也可承载多条请求，多网卡重复观察还可能重复统计。两项计数无法直接相减得到漏采请求数。捕获从记录中途开始、队列缺口和超出连接上限的流也可能无法计入记录数。漏采估计保持未知，已知丢弃为零仍需外部请求计数核对。

原始 TLS 事件与探针诊断也保存在会话内，受会话总磁盘预算约束。它们可能包含请求正文、Cookie 和认证信息，分享证据前需检查具体内容。

证据 ZIP 中的网络包按客户端端点及请求前后各 60 秒筛选，可能包含同一连接上的其他请求。HTTPS 明文来自进程探针，PCAP 保持网络原始密文。循环淘汰的包无法恢复，SHA-256 清单用于核对导出文件内容。

## 测试与兼容范围

```bash
go test -race ./...
go vet ./...
```

GitHub Actions 在 ARM64 和 x86_64 Linux 上执行格式检查、竞态测试、静态检查和构建。新增 Windows x64 原生竞态测试、静态检查及两个程序的构建，以及 Java 17/21 Maven 测试与打包。Windows 托管 runner 缺少 Npcap，两个依赖 libpcap DLL 的离线导入集成测试在 Linux 任务中运行，Windows 任务显式跳过这两项。新增 CI 任务尚待远端运行验证。单元与回归测试覆盖规则正反例、解码、分片、请求响应配对、部分正文、队列缺口、TCP 重传乱序、离线重放和证据导出。

以下实机脚本需要与本项目测试站接口兼容的既有站点，包括 `/api/health`、`/api/echo`、`/search` 及未知路径返回 404。它们会发送测试请求，串行运行，输出目录需为新目录。

```bash
python3 scripts/verify.py /tmp/traffic-functional --host 127.0.0.1
python3 scripts/benchmark.py --output /tmp/traffic-performance --host 127.0.0.1
```

脚本支持 `--binary` 和 `--config` 指定采集程序与 Nginx 配置。功能脚本另通过 `--analysis-binary` 指定证据导出所用的 `traffic-tui`，默认路径为 `/opt/traffic/bin/traffic-tui`。可用 `--ecapture` 指定探针路径、`--pid` 将 TLS 探针限定到实验进程。功能脚本检查 126 条请求及响应、已有 HTTPS 连接、TLS 版本、中文正文、五类规则、网站配置和 PID、证据校验。性能脚本默认 20/100 请求每秒、每组五分钟、重复三轮。

### 已知限制与待验收能力

- HTTP/2、HTTP/3、WebSocket 内容解析、通用 JSSE/Go TLS 和 Tomcat NIO2 尚未支持。HTTP/1.1 流缺失消息开头时，可恢复内容受限。
- Windows 已完成 Npcap HTTP、IIS / TLS 1.2 及 Nginx、Apache / TLS 1.2、1.3 的实验验收。其他 Windows Web 服务、IIS TLS 1.3、IIS 内核缓存直接命中、应用池进程替换、长期性能和 Frida 运行时完整卸载尚未验收。IIS 附加启动窗口仍可能漏采。
- Linux x86_64 的实机 HTTPS 验收覆盖 Nginx / OpenSSL 3.5。Apache、Tomcat、通用 OpenSSL 服务及长期性能仍待该架构单独验收。Linux ARM64 的多服务结果见验证记录。
- 代理后的来源地址依赖可信代理配置及代理正确维护转发头，默认使用连接对端。
- Web 已覆盖令牌鉴权、静态资源、筛选、详情及导出测试，并完成真实 IIS 历史会话的接口读取检查。已用持续写入的测试会话验证浏览器新增请求刷新、待响应详情补全和告警计数更新。当前账户缺少 BPF 采集权限，真实网卡采集至浏览器的完整链路仍待实机验收。

## 第三方组件

两个程序的依赖及版本见 `go.mod`、`go.sum`。eCapture 以独立子进程运行，固定源码、补丁和构建方式随仓库提供。第三方版权与许可证说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
