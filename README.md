<p align="center">
  <img src="docs/assets/traffic-banner.svg" alt="traffic — 网站应急响应流量采集与分析" width="100%">
</p>

<p align="center">
  <strong>把网站请求、响应、检测依据与网络证据，放进同一个可回看的会话。</strong>
</p>

<p align="center">
  <a href="https://github.com/Sunmedalia/traffic/actions/workflows/ci.yml"><img src="https://github.com/Sunmedalia/traffic/actions/workflows/ci.yml/badge.svg" alt="Checks"></a>
  <a href="https://github.com/Sunmedalia/traffic/releases"><img src="https://img.shields.io/github/v/release/Sunmedalia/traffic?color=197a69" alt="Release"></a>
  <img src="https://img.shields.io/badge/Go-1.26.7%2B-00ADD8?logo=go&logoColor=white" alt="Go 1.26.7+">
  <img src="https://img.shields.io/badge/采集-Linux%20%7C%20Windows-263c50" alt="采集平台 Linux 和 Windows">
  <img src="https://img.shields.io/badge/界面-终端%20%7C%20Web%20%7C%20JSON-4AA8A8" alt="终端、Web 与 JSON 界面">
</p>

<p align="center">
  <a href="#界面预览">界面预览</a> ·
  <a href="#下载与安装">下载安装</a> ·
  <a href="#快速开始">快速开始</a> ·
  <a href="#选择采集后端">选择后端</a> ·
  <a href="#分析会话">分析会话</a> ·
  <a href="#如何判断采集完整性">完整性</a> ·
  <a href="docs/guide.md">使用手册</a>
</p>

---

## 为什么使用 traffic

`traffic` 面向网站应急响应：在目标机上保存 HTTP/HTTPS 请求与响应，停采后在本地还原与检测，通过中文终端、浏览器或 JSON 命令分析，再导出带 SHA-256 清单的证据 ZIP。

| 🛰️ 采集现场 | 🔍 分析请求 | 🗂️ 留存证据 |
| :--- | :--- | :--- |
| 网卡抓包与可选的 TLS 明文探针 | 概览、时间线、请求、告警聚合、健康状态 | 不可变的本地分析结果与规则快照 |
| 按进程、端口及服务选择目标 | 组合筛选、命中高亮、参数与解码工具 | 循环 PCAP、探针明文事件、采集状态 |
| 缺口、截断、退出状态显式记录 | 终端、Web、JSON 读取同一份结果 | 按请求导出正文、关联包与诊断 |

```mermaid
flowchart LR
    A[目标服务] -->|网络包 / 明文探针| B[traffic capture]
    B --> C[(会话目录)]
    C -->|复制到分析机| D[traffic-console analyze]
    D --> E[终端 · Web · JSON]
    D --> F[证据 ZIP + SHA-256]
```

> [!IMPORTANT]
> **当前发布边界**：HTTP/2 已有有界解析和自动化回归，完整后端实机矩阵仍待验收。持续高负载仍有接收队列溢出样本，低影响门槛、八小时长压和部分后端排空确认尚未完成。已知缺口见 [优化进度](OPTIMIZATION.md)，实测结果见 [验证记录](VALIDATION.md)，本轮修复见 [边界审核](docs/boundary-review-2026-11-17.md)。

## 界面预览

<table>
  <tr>
    <td width="50%"><img src="docs/assets/tui/02-overview.png" alt="终端概览：指标、时间线、规则与来源分布"></td>
    <td width="50%"><img src="docs/assets/tui/06-detail-side.png" alt="终端详情：请求与响应左右并排"></td>
  </tr>
  <tr>
    <td align="center"><sub><b>终端 · 概览</b>：指标卡、请求与告警时间线、规则 / 来源 / 级别 / 状态分布</sub></td>
    <td align="center"><sub><b>终端 · 详情</b>：请求与响应同屏，可切换左右、上下或单独查看</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/assets/web/web-request-desktop.png" alt="Web 请求列表与详情"></td>
    <td width="50%"><img src="docs/assets/web/web-session-analysis.png" alt="Web 分析会话对话框"></td>
  </tr>
  <tr>
    <td align="center"><sub><b>Web · 请求</b>：筛选栏、请求列表与请求 / 响应并排详情</sub></td>
    <td align="center"><sub><b>Web · 分析</b>：选择规则重新分析当前会话</sub></td>
  </tr>
</table>

## 下载与安装

从 [Releases](https://github.com/Sunmedalia/traffic/releases) 下载对应系统、架构与组件的包，用同版本 `SHA256SUMS` 核对。**采集器和分析器分开下载，推荐同版本配对使用**：只采集时下载 `traffic`，查看会话时下载 `traffic-console`（原 `traffic-tui`）。

| 平台 | 采集器 `traffic` | 分析器 `traffic-console` |
| :--- | :--- | :--- |
| Ubuntu x64 / ARM64 | `traffic-v0.1.7-ubuntu-{amd64,arm64}.tar.gz` | `traffic-console-v0.1.7-ubuntu-{amd64,arm64}.tar.gz` |
| CentOS 7+ x64 / ARM64 | `traffic-v0.1.7-centos7-{amd64,arm64}.tar.gz` | `traffic-console-v0.1.7-centos7-{amd64,arm64}.tar.gz` |
| Windows x64 | `traffic-v0.1.7-windows-amd64.zip` | `traffic-console-v0.1.7-windows-amd64.zip` |

```bash
# Ubuntu x64；CentOS 改用 centos7-amd64 文件名
tar -xzf traffic-v0.1.7-ubuntu-amd64.tar.gz
cd traffic-v0.1.7-ubuntu-amd64
./traffic --cn-help
sudo ./traffic doctor
sudo ./traffic capture --ports 80,443 --duration 60s
```

- **Linux**：主程序静态链接 libpcap，无需安装运行库；采集包内置配套 eCapture、Java Agent 和 glibc 2.17 基线的 OpenSSL 预加载库。Ubuntu/CentOS 包使用同一兼容构建基线，并分别在干净的发行版容器中检查。
- **Windows**：采集包内置 WinDivert 签名驱动、Python、Frida 和探针脚本，**无需安装 Npcap、系统 Python 或下载独立依赖包**。完整解压后直接运行 `doctor`，管理员终端执行 `capture` 时按需加载随包驱动；不要只复制 exe。详见 [Windows 随包依赖](docs/windows-dependencies.md)。
- **自检**：`traffic doctor` 默认显示中文分区自检报告，脚本读取用 `traffic doctor --json`。帮助页面（`--cn-help`）包含每个命令的专属参数和示例。
- **数据目录**：首次启动会在程序旁创建 `sessions/` 和 `exports/`，从其他目录启动也使用同一默认位置；源码构建位于 `bin/` 时创建在项目根目录。显式 `--data-dir` / `--output` 按指定路径处理，请将程序解压到可写目录。

HTTPS 能力取决于目标与内核：CentOS 7 原生内核不具备 CO-RE BTF，需要服务启动时加载随包预加载库，程序不会重启业务服务；Java attach 依赖目标 JVM 自身的 attach 能力。

<details>
<summary><b>从源码构建</b></summary>

需要 Go 1.26.7+、CGO 和 C 编译器：

```bash
sudo apt-get update
sudo apt-get install -y build-essential libpcap-dev git
git clone --branch v0.1.7 https://github.com/Sunmedalia/traffic.git
cd traffic
./scripts/build-linux.sh
```

macOS 可从源码构建分析器：`go build -o bin/traffic-console ./cmd/traffic-console`。其他构建方式见 [分平台构建](docs/guide.md#构建分平台)。

</details>

## 快速开始

### ① 采一段 HTTP

```bash
# 指定业务的实际 HTTP 端口；--no-tls 不启动明文探针
sudo ./traffic capture --no-tls --ports 80,8080 \
  --duration 60s --output ./sessions/first-capture
```

省略接口时，Linux 使用 `any`，包含回环。省略 `--output` 时自动存入程序旁的 `sessions/`。程序在 stderr 打印会话路径；`Ctrl+C` 正常停止并保存摘要。

### ② 本地分析并打开会话

```bash
# 停采后把会话目录复制到分析机，先执行本地分析
./traffic-console analyze --session ./sessions/first-capture

# 中文终端界面；无参数时进入会话选择页
./traffic-console --session ./sessions/first-capture

# 浏览器界面；打开启动时打印的完整令牌地址
./traffic-console web --session ./sessions/first-capture
```

### ③ 按需启用 HTTPS 明文采集

现代 Linux 的 OpenSSL 服务默认使用采集包中的配套 eCapture，无需额外下载或指定路径：

```bash
sudo ./traffic doctor --service nginx --ports 443
sudo ./traffic capture --service nginx --ports 443 --duration 60s --output ./sessions/https-capture
```

eCapture 走进程明文读取路径，无需安装 CA 或解密 PCAP。附加存在启动窗口；用已知请求的唯一编号逐条核对请求、响应和正文，不能只根据 `attached` 或零丢弃判定采全。自行开发探针时可使用 `scripts/build-ecapture.sh`，或通过 `--ecapture` 覆盖默认路径。

## 采集与本地分析分离

`traffic capture` / `traffic import` 只保存原始网络包、探针明文事件和元数据，不执行 TCP/HTTP 还原、配对、索引、规则匹配或告警外送。`traffic-console analyze` 在分析机上完成这些步骤：

```bash
./traffic-console analyze --session ./sessions/first-capture
# 追加自定义规则；每次 analyze 都重新计算并替换上次结果
./traffic-console analyze --session ./sessions/first-capture --rules ./rules.yaml
```

- **结果可回滚**：结果写入不可变的 `analysis-*.sqlite`，由 `analysis-current.json` 原子选择当前版本。失败或取消保留上次完整结果；PCAP、TLS 原始事件及采集状态保持只读。
- **构建位置**：分析在会话目录内生成隐藏的 `.analysis-build-*.sqlite`，完成后改名发布，不占用系统临时目录（常见为内存 tmpfs），需确保会话所在磁盘有足够空间。
- **正文上限**：请求与响应正文的本地还原、检测上限默认各 1 MiB，可用 `--request-limit` / `--response-limit` 调大后重跑，最大各 16 MiB。提高上限只能重新读取原始流量，无法补回实际漏采的字节。
- **会话布局**：新会话使用布局 v3，采集阶段没有 `index.sqlite`，未分析时只能查看采集状态。旧版带 `index.sqlite` 的会话仍可打开和重新匹配规则，旧会话仅追加告警分析，不改原索引。

<details>
<summary><b>从 v0.1.2 及更早版本升级</b></summary>

v0.1.3 起使用采集与本地分析分离流程。旧版 v0.1.2 采集时直接检测并写 `index.sqlite`，使用旧发行包请参考 [v0.1.2 发布说明](docs/releases/v0.1.2.md)。

`--request-limit`、`--response-limit`、`--rules`、`--scan-window`、`--scan-paths`、`--alert-webhook` 已移到 `traffic-console analyze`；规则校验改用 `traffic-console rules check FILE`。`--retention` 已删除；`--no-detect` 仅保留为采集器兼容参数。**升级后请先执行 `traffic-console analyze`，再浏览新采集的会话。**

</details>

## 选择采集后端

| 环境 | 方式 | 需要重启目标 | 主要边界 |
| :--- | :--- | :---: | :--- |
| 普通 HTTP | `--no-tls` | 否 | 明文协议与选定端口 |
| Linux nginx / Apache | eCapture / eBPF | 否 | 内核能力、动态 libssl、附加窗口 |
| 通用 OpenSSL | `--service openssl --pid N` | 否 | 指定进程；自定义 BIO 需逐项验证 |
| 旧内核 / 无 BTF | OpenSSL 预加载库 | **是** | 显式启动加载；队列丢弃和退出尾部仍有边界 |
| Tomcat NIO | `--java-attach` | 否 | JDK 17/21；目标需允许动态附加 |
| Windows IIS | WinDivert + IIS 探针 | 否 | 随包自动配置 Frida；已有异步接收可能漏采 |
| Windows nginx / Apache | WinDivert + OpenSSL 探针 | 否 | 静态 OpenSSL 按二进制哈希匹配 profile |
| 已有明文 HTTP PCAP | `traffic import` | 不涉及 | 加密 PCAP 本身不能还原 HTTPS 明文 |

Linux ARM64/x64、CentOS 7、Windows 的实机样本覆盖范围各不相同，完整矩阵见 [验证范围](docs/guide.md#验证范围)。[后端参数与操作步骤 →](docs/guide.md#常见场景复制即用)

## 分析会话

终端和 Web 的页面、筛选条件与操作逻辑保持一致，读取同一份分析结果；JSON 命令适合脚本和归档。

### 🖥️ 终端

`traffic-console` 默认进入会话列表（按日期分组，只有一个会话时直接打开），打开后分为四页：

| 页面 | 内容 |
| :--- | :--- |
| **1 概览** | 六项指标卡；请求与告警时间线（纵轴峰值、整点刻度，键盘或鼠标拖动选择时间段）；命中规则、来源地址、告警级别、响应状态；最近告警与采集状态。`Enter` 跳到对应请求 |
| **2 请求** | 列表上方显示筛选后的时间线，`t` 选择时间范围；详情含 **请求/响应**、**参数**、**解码**、**解压正文**、**检测依据** 标签 |
| **3 告警** | 逐条列表，`v` 切换按规则、按来源聚合，聚合行 `Enter` 下钻 |
| **4 健康** | 缺口、排空、退出确认、探针、资源限制与采集错误 |

> [!TIP]
> 支持鼠标：点击标签、列表行、详情标签、筛选条件和底部按键提示；滚轮或右侧滚动条滚动列表，滚轮滚动详情；在时间线上拖动选择时间段；概览单击看摘要、双击进入；右键返回上一层。按 `M` 可把鼠标还给终端选取文字。

<details>
<summary><b>常用按键</b></summary>

| 按键 | 操作 |
| :--- | :--- |
| `1`–`4` · `s` | 切换页面 · 返回会话列表 |
| `/` · `x` | 筛选面板（关键词、URL 解码匹配、级别、状态、方法、静态资源、排除词、参数、来源、规则、服务、时间） · 清空筛选 |
| `Enter` · `Esc` | 打开详情或下钻 · 返回上一层 |
| `j` / `k` · `↑` / `↓` | 详情中上下一条 · 滚动 |
| `[` / `]` · `L` · `<` / `>` | 切换详情标签 · 请求与响应排版（左右 / 上下 / 单独） · 调整列表与详情宽度 |
| `d` · `f` · `i` | 解码工具（URL、Base64、Hex、HTML、Unicode、JWT、Gzip，可连续解码） · JSON 格式化 · 记录信息 |
| `c` / `m` / `H` / `S` | 按来源 / 规则 / Host / 服务筛选，再按取消 |
| `A` | 分析面板：用内置或规则目录中的规则重新分析当前会话 |
| `e` · `y` · `Y` | 导出证据 · 复制请求 ID · 复制当前标签内容 |
| `空格` · `r` · `z` | 暂停刷新 · 立即刷新 · 切换本地时间 / UTC |
| `M` | 关闭或开启鼠标操作 |

光标离开最新记录后列表定格，避免新数据打断浏览；`g` 回到最新。按 `?` 查看全部快捷键，[完整说明 →](docs/guide.md#终端界面)

</details>

<details>
<summary><b>更多终端截图</b></summary>

| | |
| :---: | :---: |
| <img src="docs/assets/tui/01-sessions.png" alt="会话列表"><br><sub>会话列表</sub> | <img src="docs/assets/tui/05-requests-timeline.png" alt="在时间线上选择时间范围"><br><sub>请求列表：在时间线上选择时间范围</sub> |
| <img src="docs/assets/tui/07-detail-stack.png" alt="请求与响应上下排列"><br><sub>详情：请求与响应上下排列</sub> | <img src="docs/assets/tui/09-detail-params.png" alt="参数标签"><br><sub>详情：参数标签，Enter 解码</sub> |
| <img src="docs/assets/tui/10-detail-alerts.png" alt="检测依据"><br><sub>详情：记录信息与检测依据</sub> | <img src="docs/assets/tui/11-decoder.png" alt="解码工具"><br><sub>解码工具：JWT</sub> |
| <img src="docs/assets/tui/12-filter.png" alt="筛选面板"><br><sub>筛选面板</sub> | <img src="docs/assets/tui/14-analysis.png" alt="分析面板"><br><sub>分析面板</sub> |

截图使用示例数据。

</details>

### 🌐 Web

```bash
./traffic-console web --session ./sessions/first-capture
```

Web 提供概览、请求与告警时间线（拖选时间段）、组合筛选、命中高亮、请求/响应并排详情、JSON 格式化、解码工具和证据导出。地址栏保留当前视图，可分享给持有访问令牌的同事。默认只监听回环，远程查看可使用 SSH 转发：

```bash
ssh -L 8080:127.0.0.1:8080 user@capture-host
```

### 📜 规则与重新分析

Web 侧边栏的「会话规则」（`#/rules`）支持新建、导入、编辑、实时校验、保存、下载和删除 YAML 文件，并预览解析出的规则。打开会话后，Web 顶栏的「分析」或终端的 `A` 可选择规则、启动或停止后台任务，并查看该会话的最近任务，完成后自动更新告警。

规则默认存放在程序旁的 `rules/`（源码 `bin/` 构建使用项目根目录），可用 `--rules-dir /path/to/rules` 指定（`web` 与终端界面均支持）。内置规则只读，自定义文件按需追加，修改文件后需重新分析。[规则目录说明 →](rules/README.md)

### 🧾 JSON 查询与证据导出

```bash
./traffic-console status --session ./sessions/https-capture
./traffic-console events --session ./sessions/https-capture --severity medium
./traffic-console show REQUEST_ID --session ./sessions/https-capture
./traffic-console export REQUEST_ID --session ./sessions/https-capture --out ./evidence.zip
```

`--severity medium` 表示中危及以上。**导出前需要停止采集**，同名 ZIP 不覆盖。

## 如何判断采集完整性

```text
sessions/<host>/<date>/<session>/
├── manifest.json          构建、主机与采集条件
├── status.json            心跳、计数、资源及退出状态
├── gaps.jsonl             已知缺口及计量单位
├── analysis-current.json  本地分析成功后创建的结果指针
├── analysis-*.sqlite      本地还原、索引、告警与规则快照
├── packets/               顺序分段 PCAP，HTTPS 仍是密文
├── tls/stream.jsonl       探针明文原始事件（按需创建）
└── logs/                  诊断日志
```

| 关注点 | 看什么 | 怎么理解 |
| :--- | :--- | :--- |
| **已知丢失** | `gap_counts`、`gaps.jsonl`、`tls_dropped`、`queue_dropped`、`dropped` | 各指标单位不同，不可当成漏采请求数相加 |
| **未知覆盖** | `tls_coverage=unverified`、`tls_missing_estimate=null` | 启动窗口和探针盲区未量化，零观测丢弃不能证明完整 |
| **退出确认** | `drain_state`、`probe_exits` | 区分数据排空、hook 恢复及运行时状态；停止辅助进程不代表目标内探针完全卸载 |

采集端不按 HTTP 正文截断，也不清理索引；PCAP 分段顺序保留，达到会话磁盘预算（默认 2 GiB）时停止。磁盘检查有间隔，预算不是硬字节上限；剩余空间低于 512 MiB 也会停止。探针仍有单事件、队列和附加覆盖限制。采集器及子进程默认限制 256 MiB、单核 50%，不包含目标进程内探针开销。完整参数见 [资源与证据限制](docs/guide.md#资源与证据限制)。

## 文档与开发

| 入口 | 内容 |
| :--- | :--- |
| 📘 [使用手册](docs/guide.md) | 后端、规则、终端与 Web、Windows、参数、停止与回滚、故障排查 |
| ✅ [验证记录](VALIDATION.md) | 实机环境、构建哈希、成功与失败样本 |
| 📈 [优化进度](OPTIMIZATION.md) | 已实现机制、性能门槛与待完成项目 |
| 🏷️ [v0.1.7 发布说明](docs/releases/v0.1.7.md) | 本版变化与已知限制；历史版本见 [docs/releases](docs/releases) 与 [Releases](https://github.com/Sunmedalia/traffic/releases) |
| ⚖️ [第三方组件](THIRD_PARTY_NOTICES.md) | 依赖、探针与许可证说明 |

```bash
go test -race ./...
go vet ./...
```

CI 覆盖 Linux ARM64/x64、Windows 原生测试与构建、Java 17/21，以及固定版本 eCapture 补丁回归。CI 通过不替代实际服务的完整性和性能验收。发布包附带依赖许可证；WinDivert、Frida 和 eCapture 的许可分别适用。
