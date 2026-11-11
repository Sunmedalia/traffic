# traffic

面向 Linux 网站应急响应的流量采集与分析工具。使用独立的采集程序记录现场数据，再通过 TUI 分析程序实时查看或回看会话。HTTP 请求、响应、检测依据和网络证据保存在同一个会话目录。

当前为 **Linux ARM64 实验版本**，已在 Debian 13、Linux 6.12、Nginx 1.26、OpenSSL 3.5 环境验证。运行中采集使用网卡抓包和 eBPF TLS 探针，采集过程无需重启或重载网站、修改网站配置。兼容性和性能验收状态见 [验证记录](VALIDATION.md)。

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

HTTPS 路径使用固定版本 eCapture 加本项目补丁。当前构建脚本生成 **ARM64 / OpenSSL 3.5 / CO-RE** 探针，其他 TLS 实现需要单独适配和验证。

```bash
# 另外需要 Go 1.26+，以及上游 eCapture 所需构建环境
sudo apt-get install -y clang llvm bpftool libelf-dev libssl-dev flex bison make file pkg-config
./scripts/build-ecapture.sh /tmp/traffic-ecapture-build
```

构建目录必须不存在。脚本检出上游提交 `143e771cf2b4919aedc27fd7b4b24ff87b8725b9`，应用补丁并生成 `bin/ecapture`、许可证和校验文件。构建细节见 [eCapture 构建文档](https://github.com/gojue/ecapture/blob/v2.9.1/docs/agent/build-test.md)。

补丁修复实机发现的连接缓存崩溃和 FD 复用时的元数据竞争，并减少解码复制。socket 地址及 inode 身份与对应明文一起进入事件。补丁扩展了内部 eBPF ABI，需要配套构建探针字节码与用户态解码器。[补丁文件](patches/ecapture-v2.9.1-connection-cache.patch)

## 快速使用

在目标 Linux 主机执行，使用 `doctor` 确认接口、权限、内核 BTF 和 Nginx 加载的 TLS 库。

```bash
./bin/traffic doctor

sudo ./bin/traffic capture \
  --interfaces eth0 \
  --ports 80,443 \
  --ecapture "$PWD/bin/ecapture" \
  --libssl /lib/aarch64-linux-gnu/libssl.so.3 \
  --output ./sessions/incident-001
```

将 `eth0` 与 `--libssl` 替换为目标主机的实际值。默认接口为 Linux `any`，包含回环接口。`--ports` 限定网卡抓包范围，TLS 探针按自动发现的 Nginx worker UID 过滤，再接收 Nginx 事件。指定 `--pid` 可以限定单个 worker。多站点共用进程时，TLS 事件可能包含其他站点的请求。

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

## 终端交互界面

使用独立的分析程序，在交互式终端打开正在采集或已经结束的会话。

```bash
./bin/traffic-tui --session ./sessions/incident-001

# 每两秒刷新，并预设筛选条件
./bin/traffic-tui --session ./sessions/incident-001 \
  --refresh 2s --client 192.0.2.10 --severity high
```

中文界面提供采集概览、请求列表和告警列表。概览显示累计请求和告警命中、网络包、各类丢弃、TLS 状态、资源限制及采集错误。列表每页 100 条，支持按客户端、规则、严重程度、起始时间和 Host/URL 关键词组合筛选。起始时间使用 RFC3339，例如 `2026-11-11T10:00:00+08:00`。规则和严重程度组合筛选要求同一条告警同时匹配。

| 按键 | 操作 |
| --- | --- |
| `1` / `2` / `3` | 切换概览、请求、告警 |
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

GitHub Actions 在 ARM64 Linux 上执行格式检查、竞态测试、静态检查和构建。单元与回归测试覆盖规则正反例、解码、分片、请求响应配对、部分正文、队列缺口、TCP 重传乱序、离线重放和证据导出。

以下实机脚本需要与本项目测试站接口兼容的既有站点，包括 `/api/health`、`/api/echo`、`/search` 及未知路径返回 404。它们会发送测试请求，串行运行，输出目录需为新目录。

```bash
python3 scripts/verify.py /tmp/traffic-functional --host 127.0.0.1
python3 scripts/benchmark.py --output /tmp/traffic-performance --host 127.0.0.1
```

脚本支持 `--binary` 和 `--config` 指定采集程序与 Nginx 配置。功能脚本另通过 `--analysis-binary` 指定证据导出所用的 `traffic-tui`，默认路径为 `/opt/traffic/bin/traffic-tui`。功能脚本检查 126 条请求及响应、已有 HTTPS 连接、TLS 版本、中文正文、五类规则、网站配置和 PID、证据校验。性能脚本默认 20/100 请求每秒、每组五分钟、重复三轮。

HTTP/2、HTTP/3、WebSocket 内容解析、Java/Go TLS、Windows 及 x86_64 的完整采集验收待实现。HTTP/1.1 流中途缺失消息开头时，可见内容受限。代理后的来源地址默认取连接对端，经过 CDN 或负载均衡时需结合可信代理信息分析。

## 第三方组件

两个程序的依赖及版本见 `go.mod`、`go.sum`。eCapture 以独立子进程运行，固定源码、补丁和构建方式随仓库提供。第三方版权与许可证说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
