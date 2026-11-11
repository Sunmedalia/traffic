# traffic

面向 Linux 网站应急响应的流量分析命令行工具。在攻击仍持续时启动采集，将 HTTP 请求、响应、检测依据和网络证据放到同一个会话中查询。

当前为 **Linux ARM64 实验版本**，已在 Debian 13、Linux 6.12、Nginx 1.26、OpenSSL 3.5 环境验证。运行中采集使用网卡抓包和 eBPF TLS 探针，采集过程无需重启或重载网站、修改网站配置。兼容性和性能验收状态见 [验证记录](VALIDATION.md)。

## 能力

- 捕获选定网卡和 TCP 端口的原始流量，以循环 PCAP 保留证据。
- 还原 HTTP/1.1 请求与响应，处理 TCP 分段、乱序、重传、长连接和分片正文。
- 从运行中的 Nginx/OpenSSL 获取 HTTPS 明文，支持 TLS 1.2/1.3 和采集启动前已建立的连接。
- 检测疑似 SQL 注入、命令注入、路径穿越、敏感文件探测和扫描行为，显示匹配片段及解码来源。
- 使用 SQLite 查询全部请求或告警，导出请求、响应、关联 PCAP 和 SHA-256 校验清单。
- 提供正文大小、队列、磁盘和 cgroup 资源限制，报告截断、数据缺口与采集失败。

## 构建

主程序需要 Linux、Go 1.26+、CGO 和 libpcap。以下以 Debian/Ubuntu 为例。

```bash
sudo apt-get update
sudo apt-get install -y build-essential libpcap-dev git

git clone https://github.com/Sunmedalia/traffic.git
cd traffic
./scripts/build-linux.sh
./bin/traffic doctor
```

构建脚本执行竞态测试、`go vet`，随后生成 `bin/traffic` 和校验文件。普通 HTTP 采集可通过 `--no-tls` 使用主程序。

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
./bin/traffic status --session ./sessions/incident-001
./bin/traffic events --session ./sessions/incident-001
./bin/traffic requests --client 192.0.2.10 --session ./sessions/incident-001

# 查看完整记录，EVENT_ID 来自列表结果
./bin/traffic show EVENT_ID --session ./sessions/incident-001

# 停止采集后导出，目标文件必须不存在
./bin/traffic export EVENT_ID \
  --session ./sessions/incident-001 \
  --out ./evidence.zip
```

列表返回 JSON 摘要，`show` 包含可读正文及 base64 字节字段。保存的 HTTP 文本由解析器重新序列化，原始网络字节保留在 PCAP 中。可按 `--since`（RFC3339）、`--client`、`--rule`、`--severity` 和 `--limit` 查询。

```bash
# 60 秒普通抓包与 HTTP 分析
sudo ./bin/traffic capture --no-tls --duration 60s --output ./sessions/http-001

# 离线分析明文 HTTP 流量
./bin/traffic analyze capture.pcap --ports 80,8080 --output ./sessions/offline-001

# 查看所有选项
./bin/traffic capture --help
```

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

脚本支持 `--binary` 和 `--config` 指定工具与 Nginx 配置。功能脚本检查 126 条请求及响应、已有 HTTPS 连接、TLS 版本、中文正文、五类规则、网站配置和 PID、证据校验。性能脚本默认 20/100 请求每秒、每组五分钟、重复三轮。

HTTP/2、HTTP/3、WebSocket 内容解析、Java/Go TLS、Windows 及 x86_64 的完整采集验收待实现。HTTP/1.1 流中途缺失消息开头时，可见内容受限。代理后的来源地址默认取连接对端，经过 CDN 或负载均衡时需结合可信代理信息分析。

## 第三方组件

主程序依赖及版本见 `go.mod`、`go.sum`。eCapture 以独立子进程运行，固定源码、补丁和构建方式随仓库提供。第三方版权与许可证说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
