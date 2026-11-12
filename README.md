# traffic

面向 Linux 网站应急响应的流量采集与分析工具。使用独立的采集程序记录现场数据，再通过 TUI 分析程序实时查看或回看会话。HTTP 请求、响应、检测依据和网络证据保存在同一个会话目录。

当前为 **Linux ARM64 / x86_64 实验版本**。ARM64 已在 Debian 13、Linux 6.12、Nginx 1.26、OpenSSL 3.5 环境验证，x86_64 已在 Ubuntu 26.04、Linux 7.0、Nginx 1.28、OpenSSL 3.5 环境验证。运行中采集使用网卡抓包和 eBPF TLS 探针，采集过程无需重启或重载网站、修改网站配置。兼容性和性能验收状态见 [验证记录](VALIDATION.md)。

另提供 **Windows x64 HTTP 实验版本**，已在 Windows 10 LTSC 17763 上完成 Npcap 抓包、HTTP 请求响应还原和证据导出测试。IIS / TLS 1.2 已完成显式启用的动态 HTTP Server API 明文采集验收。启动前已投递的接收调用存在漏采窗口，完整边界见验证记录。

## 程序职责

| 程序 | 源码入口 | 功能 |
| --- | --- | --- |
| `traffic` | `cmd/traffic` | `doctor` 检查采集环境，`capture` 实时采集，`import` 将已有 PCAP 转为会话，`rules check` 校验采集规则 |
| `traffic-tui` | `cmd/traffic-tui` | 默认打开中文 TUI，分析会话中的请求、响应和告警，提供 `status`、`requests`、`events`、`show`、`export` 查询及证据导出命令 |

采集程序负责网卡抓包、TLS 探针、协议还原、规则初筛、会话写入和资源管理。分析程序读取会话索引及证据，提供筛选、详情浏览和导出。两者通过版本化的 SQLite、JSON 和 PCAP 会话文件交换数据，可分别启动和部署。`internal/session` 定义共享的数据结构、数据库布局和正文解码逻辑。

升级时将原来的 `traffic tui` 改为 `traffic-tui`，将 `traffic status/requests/events/show/export` 的程序名改为 `traffic-tui`。原来的 `traffic analyze` 改名为 `traffic import`，用于把离线 PCAP 还原并写入新会话。

## 能力

- 捕获选定网卡和 TCP 端口的原始流量，以循环 PCAP 保留证据。
- 还原 HTTP/1.1 请求与响应，处理 TCP 分段、乱序、重传、长连接和分片正文。
- 从运行中的 Nginx/OpenSSL 获取 HTTPS 明文，支持 TLS 1.2/1.3 和采集启动前已建立的连接。
- 检测疑似 SQL 注入、命令注入、路径穿越、敏感文件探测和扫描行为，显示匹配片段及解码来源。
- 使用 SQLite 查询全部请求或告警，导出请求、响应、关联 PCAP 和 SHA-256 校验清单。
- 提供正文大小、队列、磁盘和 cgroup 资源限制，报告截断、数据缺口与采集失败。

## 构建

构建需要 Go 1.26.7+ 和 CGO。采集程序需要 Linux 和 libpcap，分析程序通过 Go 读取 PCAP，依赖 SQLite 驱动。以下以 Debian/Ubuntu 为例。

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

单独构建分析程序需要 C 编译器，可在 Linux 或 macOS 上执行。

### HTTPS 采集依赖

HTTPS 路径使用固定版本 eCapture 加本项目补丁。当前构建脚本按 Linux 主机架构生成 **ARM64 或 x86_64 / OpenSSL 3.0、3.5 / CO-RE** 探针，并包含自定义 BIO 的 socket 关联以及 `SSL_read_ex`、`SSL_write_ex` 支持。其他版本需要单独验证。

```bash
# 另外需要 Go 1.26+，以及上游 eCapture 所需构建环境
sudo apt-get install -y clang llvm bpftool libelf-dev libssl-dev flex bison make file pkg-config
./scripts/build-ecapture.sh /tmp/traffic-ecapture-build
```

构建目录必须不存在。脚本检出上游提交 `143e771cf2b4919aedc27fd7b4b24ff87b8725b9`，应用补丁并生成 `bin/ecapture`、许可证和校验文件。构建细节见 [eCapture 构建文档](https://github.com/gojue/ecapture/blob/v2.9.1/docs/agent/build-test.md)。

补丁修复实机发现的连接缓存崩溃和 FD 复用时的元数据竞争，并减少解码复制。socket 地址及 inode 身份与对应明文一起进入事件。多核机器上的 TLS 事件使用 100 毫秒时间排序窗口，空闲时也会刷新末批事件。补丁扩展了内部 eBPF ABI，需要配套构建探针字节码与用户态解码器。[补丁文件](patches/ecapture-v2.9.1-connection-cache.patch)

### Windows 构建与测试站点

Windows x64 构建需要 Go 1.26.7+、x64 MinGW GCC，以及用于运行采集和抓包测试的 [Npcap](https://npcap.com/)。在 PowerShell 中执行以下命令。

```powershell
powershell -ExecutionPolicy Bypass -File scripts/windows/build.ps1
.\bin\windows\traffic.exe doctor
.\bin\windows\traffic.exe capture --no-tls --ports 8080,8443 --duration 60s --name windows-http
.\bin\windows\traffic-tui.exe
```

默认枚举具有地址的可用适配器及回环接口，跳过标记为断开的设备。也可使用 `doctor` 返回的完整 Npcap 设备名，例如 `--interfaces '\Device\NPF_Loopback'`。Windows 抓包快照上限为 256 KiB，避免回环帧超过 65,535 字节导致尾部丢失。PCAP 文件名使用设备名的 SHA-256，原始设备名保留在请求来源中。证据目录使用继承 ACL，授权当前用户、SYSTEM 和 Administrators。采集器使用 Job Object 限制合计 256 MiB 内存及单核 50% CPU，生效情况写入状态文件。

以下脚本为专用实验机安装 IIS、ASP.NET，并创建独立的 `TrafficLab` 站点、应用池、自签证书和防火墙规则，监听 HTTP 8080、HTTPS 8443。已有目录、同名站点或端口冲突会报错。安装组件可能要求首次重启，脚本会保留安装记录，重启后通过 `-Resume` 继续。

```powershell
powershell -ExecutionPolicy Bypass -File scripts/windows/setup-iis.ps1
# 仅在首次安装要求重启且已完成重启后执行
powershell -ExecutionPolicy Bypass -File scripts/windows/setup-iis.ps1 -Resume
python scripts/windows/verify-iis.py --binary C:\traffic\bin\windows\traffic.exe --analysis-binary C:\traffic\bin\windows\traffic-tui.exe --output C:\traffic-iis-verification
```

验收脚本发送 HTTP/1.1 请求，检查中文正文、分块、长连接、并发、大小限制、规则、配置哈希、工作进程身份及导出校验。报告记录 HTTPS 明文、启动预热漏采、卸载确认和已有连接复用。未显式启用 IIS 探针时，Windows TLS 状态报告 `unavailable`，HTTPS 网络包保存为密文。`--service iis` 根据 IIS 配置关联候选服务端口，HTTP.sys 监听端口不能直接确定具体站点或应用池。

IIS HTTPS 探针通过固定版本 Frida 17.5.1 动态附加运行中的 x64 `w3wp.exe`，在 HTTP Server API 收发边界复制明文，通过 I/O 完成关联处理异步接收，无需安装 IIS 模块或回收应用池。需安装 Python 和 Frida，并显式指定辅助脚本及临时目录。`setup-iis.ps1` 为 `TrafficLab` 应用池创建专用可读的 `C:\traffic-lab\probe-runtime`，证据目录保持独立权限。其他应用池需要对应身份可读取探针临时目录。

```powershell
python -m pip install frida==17.5.1
.\bin\windows\traffic.exe capture --service iis --ports 8080,8443 --iis-probe C:\traffic-lab\scripts\windows\probe-iis.py --iis-runtime-dir C:\traffic-lab\probe-runtime --duration 60s
python scripts/windows/verify-iis.py --binary C:\traffic-lab\bin\traffic.exe --analysis-binary C:\traffic-lab\bin\traffic-tui.exe --iis-probe C:\traffic-lab\scripts\windows\probe-iis.py --output C:\traffic-iis-https-verification
```

辅助脚本、`iis-plaintext.js` 和 `probe-iis.js` 应放在同一目录，`--iis-python` 可指定装有 Frida 的 Python。原始 API 事件保存在会话 `tls/iis-*.jsonl`，诊断在 `logs/iis-*.log`，请求记录的 backend 为 `iis-httpapi`。正文和头部按 HTTP/1.1 重建，原始 API 事件及 PCAP 保留供复核。内存队列、正文复制和磁盘均有边界，丢弃及不完整记录显式报告。

后附加无法恢复附加前已投递的异步接收调用，`attached` 表示拦截安装成功，首批请求仍可能漏采。验收将 24 次预热请求单独统计，随后检查 107 次 HTTP/HTTPS 请求。本机启动预热漏采 10 条，不能把预热后的成功视为首个请求无损。Windows 10 17763 本次验证 TLS 1.2、HTTP/1.1 和同一个 IIS 工作进程，TLS 1.3、内核缓存直接命中、HTTP/2、进程替换和长期性能尚未验收。缓存片段等无法复制的实体类型标记缺口。默认仍需显式启用动态探针。停止时逐个核对拦截位置原指令已恢复，但未完成 I/O 可能使 Frida 脚本卸载或传输断开停滞。辅助进程有界退出，Frida 运行时可能仍留在工作进程，报告单独记录 `hooks_removed`、`script_unloaded` 和 `transport_detached`，完整运行时卸载尚未验收。

仅观察调用元数据时可运行以下命令。

```powershell
python scripts/windows/probe-iis.py --pid 1234 --duration 30 --runtime-dir C:\traffic-lab\probe-runtime --out C:\traffic-iis-api.jsonl
```

`scripts/windows/restore-iis.ps1` 移除实验站点、应用池、证书和防火墙规则，保留文件与安装记录。需要同时卸载本次新增的 IIS 组件时使用 `-RemoveInstalledFeatures`，Windows 可能再次要求重启。恢复脚本应在测试结束后运行。

## 快速使用

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

## Apache、Tomcat 和其他 OpenSSL 服务

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

`field` 支持 `url`、`request`，`severity` 支持 `low`、`medium`、`high`。`--no-detect` 适合只采集和还原流量。

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
| 进程资源 | 可用时创建独立 cgroup，工具及子进程合计 256 MiB 内存、单核 50% CPU |
| 文件权限 | 会话目录 `0700`，证据文件 `0600` |

队列有界。`status.json` 记录网卡丢包、用户态队列丢弃、TLS 丢失、错误和资源限制是否生效。探针失败后最多重试一次，保留网卡采集。未完成的 TLS 消息在连接关闭、空闲超时或停止时保存为不完整证据。

原始 TLS 事件与探针诊断也保存在会话内，受会话总磁盘预算约束。它们可能包含请求正文、Cookie 和认证信息，分享证据前需检查具体内容。

证据 ZIP 中的网络包按客户端端点及请求前后各 60 秒筛选，可能包含同一连接上的其他请求。HTTPS 明文来自进程探针，PCAP 保持网络原始密文。循环淘汰的包无法恢复，SHA-256 清单用于核对导出文件内容。

## 测试与兼容范围

```bash
go test -race ./...
go vet ./...
```

GitHub Actions 在 ARM64 和 x86_64 Linux 上执行格式检查、竞态测试、静态检查和构建。单元与回归测试覆盖规则正反例、解码、分片、请求响应配对、部分正文、队列缺口、TCP 重传乱序、离线重放和证据导出。

以下实机脚本需要与本项目测试站接口兼容的既有站点，包括 `/api/health`、`/api/echo`、`/search` 及未知路径返回 404。它们会发送测试请求，串行运行，输出目录需为新目录。

```bash
python3 scripts/verify.py /tmp/traffic-functional --host 127.0.0.1
python3 scripts/benchmark.py --output /tmp/traffic-performance --host 127.0.0.1
```

脚本支持 `--binary` 和 `--config` 指定采集程序与 Nginx 配置。功能脚本另通过 `--analysis-binary` 指定证据导出所用的 `traffic-tui`，默认路径为 `/opt/traffic/bin/traffic-tui`。可用 `--ecapture` 指定探针路径、`--pid` 将 TLS 探针限定到实验进程。功能脚本检查 126 条请求及响应、已有 HTTPS 连接、TLS 版本、中文正文、五类规则、网站配置和 PID、证据校验。性能脚本默认 20/100 请求每秒、每组五分钟、重复三轮。

HTTP/2、HTTP/3、WebSocket 内容解析、通用 JSSE/Go TLS、Tomcat NIO2、Windows 的完整采集验收待实现。x86_64 的 Apache、Tomcat、通用 OpenSSL 服务及长期性能仍待单独验收。HTTP/1.1 流中途缺失消息开头时，可见内容受限。代理后的来源地址默认取连接对端，经过 CDN 或负载均衡时需结合可信代理信息分析。

## 第三方组件

两个程序的依赖及版本见 `go.mod`、`go.sum`。eCapture 以独立子进程运行，固定源码、补丁和构建方式随仓库提供。第三方版权与许可证说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
