# 使用手册

[← 返回项目首页](../README.md) · [下载版本](https://github.com/Sunmedalia/traffic/releases)

面向网站应急响应的流量采集与分析工具。在 Linux / Windows 目标机上采集 HTTP/HTTPS 请求、响应和网络证据，在本地分析时生成检测依据，用中文 TUI、浏览器或 JSON 命令回看，并导出可校验的证据包。

- **不装 CA、不改业务代码**：Linux 用 eCapture/eBPF 在 OpenSSL 读写处取明文，Windows 用随包 WinDivert 加动态探针。
- **采集与分析分离**：采集器只写会话目录，分析器可在另一台机器打开。
- **完整性显式**：状态文件记录网卡、队列、TLS 丢弃和未知缺口，不把“0 丢弃”说成“采全”。

```mermaid
flowchart LR
  A[目标服务<br/>nginx / apache / tomcat / IIS] -->|网卡 + TLS 探针| B[traffic capture]
  B --> C[会话目录<br/>SQLite + PCAP + JSONL]
  C --> D[traffic-console<br/>TUI / Web / JSON]
```

本轮采集完整性、低影响与 HTTP/2 代码改动及未完成项目见 [优化实施与验收](../OPTIMIZATION.md)。HTTP/2 已加入有界解析和合成回归，实机后端覆盖尚未验收；以下表格保留既有实机结论。

## 先跑起来（Linux）

```bash
# 1. 构建：需要 Go 1.26.7+、CGO、C 编译器、libpcap
sudo apt-get update && sudo apt-get install -y build-essential libpcap-dev git
git clone https://github.com/Sunmedalia/traffic.git && cd traffic
./scripts/build-linux.sh

# 2. 自检：接口、权限、BTF、eCapture、可发现的 TLS 库
#    此时尚未构建 eCapture，ecapture_installed=false 属正常
./bin/traffic doctor

# 3. 先验证链路：只采 HTTP，不需要 eCapture
sudo ./bin/traffic capture --ports 80,443 --no-tls

# 4. 另开终端分析；无参数会列出会话
./bin/traffic-console
```

HTTP 链路确认后，再构建 eCapture 采集 HTTPS 明文：

```bash
sudo apt-get install -y clang llvm bpftool libelf-dev libssl-dev \
  flex bison make file pkg-config
./scripts/build-ecapture.sh /tmp/traffic-ecapture-build
sudo ./bin/traffic capture --ports 80,443 --ecapture "$PWD/bin/ecapture"
```

采集器启动时在 stderr 打印会话绝对路径，停止时写入摘要。先确认这三件事再继续：

1. `status.json` 的 `tls` 为 `attached`（eBPF）或 `active-preload`（预加载），不是 `unavailable`。
2. 从客户端发一条已知请求，`traffic-console requests` 能看到对应记录。
3. 用唯一编号逐条核对请求、响应及正文；`tls_coverage` 仍是 `unverified` 表示启动窗口和探针盲区无法自动量化，不是错误。

> 只做 HTTP 时始终加 `--no-tls`。HTTPS 明文的依赖、探针版本和边界见 [Linux HTTPS 依赖](#linux-https-依赖与-ecapture)。

## 我该用哪个后端

| 你的场景 | 推荐方式 | 要重启服务吗 | 说明 |
| --- | --- | --- | --- |
| 只看 HTTP | `--no-tls` | 否 | 只需 libpcap |
| Linux nginx / apache | 默认 eBPF（eCapture） | 否 | 自动发现 worker，推荐首选 |
| HAProxy / 其他通用 OpenSSL 程序 | eBPF + `--service openssl --pid N` | 否 | 需要显式指定 PID |
| 内核太旧、无 BTF，或选择启动时符号拦截 | `LD_PRELOAD` / `ld.so.preload` | 是 | 启动时加载库；系统级预加载支持白名单 |
| Tomcat / JVM HTTPS | `--java-attach` | 否 | 动态附加 Java Agent |
| Windows IIS / nginx / apache | 随包 WinDivert + 自动配置探针 | 否 | IIS 用 Frida，nginx/apache 用 OpenSSL 探针 |
| 已有 PCAP | `traffic import` | 不涉及 | 保存为原始会话，本地 console 还原 |
| 在分析机上看别人采的会话 | `traffic-console` | 不涉及 | 支持 Linux / macOS / Windows |

## 常见场景（复制即用）

### Linux nginx / apache HTTPS

```bash
# 自动发现 nginx worker、apache2/httpd 及其 libssl
sudo ./bin/traffic capture --interfaces eth0 --ports 80,443 \
  --ecapture "$PWD/bin/ecapture" --output ./sessions/incident-001
```

`--interfaces` 省略时使用 `any`（含回环）。`--libssl` 省略时从目标进程的映射自动发现；指定错误路径会让探针挂到错误的库上。多站点共用 worker 和端口时，采集会包含这些站点。

### 指定进程或通用 OpenSSL 服务

```bash
# 通用 OpenSSL 程序必须给 PID，例如 HAProxy
sudo ./bin/traffic capture --service openssl --pid 1234 --ports 9443

# 只采一个进程，其余服务不附加
sudo ./bin/traffic capture --service nginx --pid 1234 --ports 443
```

### 旧内核与启动加载：LD_PRELOAD

```bash
# 1. 构建采集库（在目标系统构建，匹配 glibc 与 libpcap）
bash scripts/build-openssl-preload.sh

# 2. 启动采集器，等待 tls=listening-preload
sudo ./bin/traffic capture --interfaces any --ports 443 \
  --openssl-preload-socket /run/traffic/plaintext.sock \
  --output ./sessions/old-kernel

# 3a. 单服务：用环境变量加载库
sudo env LD_PRELOAD="$PWD/bin/libtraffic-openssl.so" \
  TRAFFIC_OPENSSL_SOCKET=/run/traffic/plaintext.sock /path/to/service

# 3b. 系统级：安装库、写配置、启动采集器后重启服务
sudo install -m 755 bin/libtraffic-openssl.so /opt/traffic/bin/
sudo mkdir -p /etc/traffic
sudo tee /etc/traffic/openssl-preload.conf >/dev/null <<'EOF'
socket=/run/traffic/plaintext.sock
targets=nginx
EOF
sudo ./bin/traffic capture --interfaces any --ports 443 \
  --openssl-preload-socket /run/traffic/plaintext.sock \
  --openssl-preload-allow-uid 33 --output ./sessions/incident-preload
printf '%s\n' /opt/traffic/bin/libtraffic-openssl.so | sudo tee -a /etc/ld.so.preload
sudo systemctl restart nginx
```

非 root worker 需要 `--openssl-preload-allow-uid`：socket 会变成 `0660` 并归属该 UID 的主组。未匹配 `targets` 的进程不启动采集队列；预加载库仍会被动态链接器载入。完整说明、回滚和边界见 [系统级 ld.so.preload](#系统级-ldsopreload-与不同-uid-的服务)。

### Tomcat / JVM HTTPS

```bash
./scripts/build-java-agent.sh

sudo ./bin/traffic capture --service tomcat --pid 1234 \
  --ports 8080,8443 --java-attach \
  --java-agent "$PWD/bin/traffic-java-agent.jar"
```

目标 JVM 需要允许动态附加。附加助手默认使用目标 Java；JDK 不匹配时用 `--java-helper` 指定带 `jdk.attach` 的 JDK。

### 只看 HTTP 或导入 PCAP

```bash
# 60 秒普通抓包，不启动 TLS 探针
sudo ./bin/traffic capture --no-tls --duration 60s --output ./sessions/http-001

# 将已有 PCAP 保存为会话，再在本地还原
./bin/traffic import capture.pcap --ports 80,8080 --output ./sessions/offline-001
```

### 采集多个服务、多个端口

```bash
sudo ./bin/traffic capture --service auto --ports 80,443,8081,8444,8083,8446 \
  --java-attach --java-pid 1234 --java-agent "$PWD/bin/traffic-java-agent.jar"
```

### 限时采集，再在本地加规则和外送告警

```bash
sudo ./bin/traffic capture --ports 80,443 --ecapture "$PWD/bin/ecapture" --duration 10m \
  --trusted-proxies 10.0.0.0/8,192.0.2.10 \
  --output ./sessions/incident-002

# 停采后，把整个会话复制到本地，再执行：
./bin/traffic-console analyze --session ./sessions/incident-002 \
  --rules ./rules.yaml --alert-webhook https://siem.example/traffic
```

`TRAFFIC_WEBHOOK_TOKEN` 可带 Bearer 令牌。规则格式见[检测规则](#检测规则)。

### Windows

```powershell
powershell -ExecutionPolicy Bypass -File scripts/windows/build.ps1
.\bin\windows\traffic.exe doctor
.\bin\windows\traffic.exe capture --no-tls --ports 80,443 --duration 60s --name windows-http
.\bin\windows\traffic-console.exe
```

IIS、Windows nginx/apache 和通用 OpenSSL 的探针参数见 [Windows 采集](#windows-采集)。

## 分析会话

### 终端界面

使用独立的分析程序，在交互式终端打开正在采集或已经结束的会话。

```bash
# 无参数启动，在界面选择会话
./bin/traffic-console

# 从其他采集根目录选择会话
./bin/traffic-console --data-dir /var/lib/traffic/sessions

# 直接打开指定会话
./bin/traffic-console --session ./sessions/incident-001

# 每两秒刷新，并预设筛选条件
./bin/traffic-console --session ./sessions/incident-001 \
  --refresh 2s --client 192.0.2.10 --severity high
```

无参数启动会递归扫描当前工作目录及程序所在目录对应的 `sessions/`。选择页与网页版一致：会话按开始时间从新到旧排列并按日期分组，每行显示状态、开始时间、请求数、告警数、会话名、主机和相对时间，底部显示选中会话的完整路径；计数未确认时显示 `≈`，没有计数时显示 `—`。只找到一个可用会话时直接打开。在会话目录内启动也会识别当前会话，兼容旧版平铺目录与新版分层目录。程序识别 v3 原始会话的 `manifest.json`，兼容旧版 `index.sqlite`。新会话必须先执行本地分析才能查询请求；本地请求和告警计数来自同一份分析结果，尚未分析时显示未知。旧索引损坏时标记不可用。

选择页使用 `↑` / `↓`、`j` / `k` 选择，`Enter` 打开，`/` 按会话名、主机或路径即时查找，`r` 重新扫描，`o` 输入其他采集根目录、会话目录或 `index.sqlite` 文件路径，`z` 切换本地时间与 UTC；也可以点击会话行直接打开，用滚轮移动光标。进入分析页后按 `s` 返回会话选择页，光标停在刚才的会话上。仅含 PCAP 或 HTTP 文本的导出目录需要先导入或找到对应的完整会话。

TUI 的页面、区块和操作与浏览器界面对齐，同一个会话在两边看到的统计、筛选结果和检测依据一致。分析页由五部分组成：顶部是会话身份栏（主机 / 日期 / 会话名、采集状态、累计请求与告警、刷新或分析状态）、标签栏（含时区）和当前筛选条件，底部是提示栏和当前可用按键。四个页面如下。

- **概览**：与网页概览相同。首行是累计请求、累计告警命中、网络包、网卡丢包、用户态队列丢弃和 TLS 已知丢弃六个指标；下面是请求与告警时间线：左侧纵轴标出每格峰值，横轴按整点时间刻度标注，红色为含告警的请求，标题行给出时间范围、每格时长和请求、告警合计，高度随终端调整；以及命中规则、来源地址（告警优先）、告警级别、响应状态、最近告警和采集状态。`Tab` 在区块间切换，`Enter` 的去向与网页点击一致：规则和级别进入告警列表，来源和响应状态进入请求列表，最近告警直接打开详情。在时间线上用 `←` / `→` 移动、`Shift+←` / `Shift+→` 选一段时间，`Enter` 查看这段时间内的请求，等同网页上的拖选。概览始终统计整个会话，不受筛选影响。
- **请求**：每页 100 条，列顺序与网页一致：时间、级别、方法、状态、来源、Host、URL，窄屏只保留时间、级别、方法、状态和 URL。列表上方是当前筛选条件下的时间线，按 `t` 进入时间线选择一段时间，`Enter` 后只看这段时间，与网页列表上的拖选相同。状态码按 2xx / 4xx / 5xx 着色，高危请求的 URL 标红。终端宽度至少 120 列时，详情在右半屏打开。
- **详情**：顶部显示方法、状态、不完整 / 截断标记和命中规则，下面是 Host 与 URL 和一行记录摘要（时间、来源、服务、协议、完整性原因），按 `i` 展开完整记录信息。标签有请求/响应、参数（请求带查询参数、表单参数或 Cookie 时显示）、解码、解压正文（请求和响应正文都有可用解码视图时显示）、检测依据（有告警时显示），用 `[` / `]` 或 `Tab` 切换，默认打开请求/响应。请求和响应默认在同一页左右并排显示；按 `L` 在左右、上下和单独三种排版间切换，单独时请求和响应各占一个标签。详情宽度不足 90 列时左右排版自动改为上下。`<` / `>` 调整列表与详情的宽度（各占一半、详情占三分之二、详情全屏），排版和宽度在切换会话后保留。参数标签按查询参数、表单参数和 Cookie 分组列出原文，`↑` / `↓` 选择，`Enter` 在解码工具中打开所选参数；JSON 正文默认格式化，按 `f` 切换原文。告警的匹配片段在请求、响应和正文中反色高亮，检测依据中注明规则版本、命中字段、视图、URL 解码轮数和片段在原文出现的次数。`j` / `k` 查看下一条 / 上一条（可跨页），`↑` / `↓`、`PgUp` / `PgDn` 滚动，`/` 查找当前标签的文字，`n` / `N` 在命中处之间跳转，`Y` 复制当前标签内容。
- **解码**：按 `d` 打开，与网页解码工具相同。`←` / `→` 选择来源：完整 URL、路径、查询字符串、各查询参数、Cookie、表单参数、请求正文、常用请求头和命中片段，`w` 手动输入；`Enter` 选择解码方式（URL、URL 保留 +、Base64、Hex、HTML 实体、Unicode / JS 转义、JWT、Gzip / Deflate），可连续解码，`✓` 标出当前结果适用的方式；`Backspace` 撤销一步，`X` 切换十六进制。解码只在本地进行，不改动采集数据。
- **告警**：默认是逐条告警列表，与网页告警页相同；`v` 切换到按规则、按来源两种聚合视图。按规则视图每条规则一行，显示级别、命中请求数、来源数、最近时间和最近一次匹配片段，级别高的在前；按来源视图每个客户端 IP 一行，显示命中数、涉及规则、首次和最近时间。在聚合行上按 `Enter`，把该规则或来源加入当前筛选并进入逐条视图，`Esc` 退回聚合视图并恢复原来的筛选和光标位置。聚合视图同样受筛选约束。
- **健康**：完整性提示、采集状态、停止时间、最后收包、会话目录、网络包与各类丢弃、TLS、资源限制、告警推送、服务探针和采集错误。出现丢弃、探针未附加、推送失败或采集错误时标签显示黄色 `!`，采集失败或心跳过期时显示红色 `✕`，提示栏同时给出原因。

光标停在列表第一页第一行时，新记录从顶部进入，状态为「跟随最新」。移动光标、翻页或打开详情后列表定格，行不再移动，页脚提示新增条数，按 `g` 回到最新并恢复跟随。与网页一致，已完成或已停止的会话不再自动刷新，按 `r` 立即刷新；暂停只对采集中的会话有效。

筛选对请求页和告警页同时生效，概览和健康页不受影响。`/` 打开的筛选面板与网页筛选栏的条件相同：Host/URL 关键词、URL 解码若干次后匹配、级别、响应状态类别、方法、隐藏静态资源、排除关键词、包含参数、具体状态码、来源地址、规则 ID、服务和时间范围。级别按「不低于」理解，规则和级别组合要求同一条告警同时满足。「开始时间」和「结束时间」可填 `30m`、`2h`、`1d`、`today`、`14:30`、`11-16 14:30`、`2026-11-11 10:00` 或 RFC3339，面板中实时显示换算后的时间；「结束时间」留空表示到现在，手填时包含该时刻，从时间线选择的范围与网页一样不含结束时刻。`--severity` 命令行参数和 Web 界面采用相同的「不低于」含义。

按 `A` 打开分析面板，与网页「分析」对话框相同：选择仅内置规则，或内置规则加 `--rules-dir`（默认程序旁的 `rules`）中的某个规则文件，`Enter` 开始分析。采集进行中不能分析。关闭面板后任务在后台继续，身份栏显示「分析中」和用时；面板内 `x` 停止分析，停止或失败时会话保留上次完整的分析结果。分析完成后列表、概览和详情自动换成新结果，面板中列出此会话最近的任务。分析进行中不能用 `s` 离开会话。

按 `y` 通过 OSC 52 把选中请求的 ID 复制到剪贴板，提示栏同时显示 ID，终端不支持 OSC 52 时可手动选取。设置 `NO_COLOR` 环境变量后界面不输出颜色，级别、状态和告警用文字、符号、粗体和反色区分。

TUI 支持鼠标，操作与网页点击一致：
- **点击**：点标签栏切换页面；点列表行打开详情（分栏时右侧换成这一条），再点同一行收起详情回到完整列表（快速双击不会收起）；页脚的 `‹ 上一页` / `下一页 ›` 在打开详情时同样翻页，右侧详情保持不变；点详情标签、告警视图切换、聚合行和参数行，效果与选中后按 `Enter` 相同。概览页单击某一行只选中它并在提示栏显示简要信息（如规则的级别和命中数、来源的请求与告警数、状态占比、最近告警的时间和 URL），再点一次同一行才进入对应的请求或告警，避免误点离开概览。筛选栏上点「筛选」打开筛选面板，点某个条件只去掉这一条。底部提示栏和页面里的按键提示（如 `L 排版`、`f 原文`、`x 清空`、`‹ 上一页` / `下一页 ›`）点一下等于按下对应的键。筛选、导出和分析面板提供可点击的选项和按钮。
- **滚轮与滚动条**：滚轮滚动列表、详情和健康页；分栏时在哪一侧滚动就滚动哪一侧，滚动左侧列表不会换掉右侧详情。请求和告警列表一页放不下时，右侧显示滚动条，拖动滑块滚动本页，点击滑块外的位置直接翻到那里。
- **分隔线**：分栏时拖动列表与详情之间的竖线可自由调整两侧宽度（列表至少 30 列、详情至少 50 列），比例在调整终端大小和切换会话后保留；双击分隔线恢复各占一半，`<` / `>` 回到固定档位。
- **右键**：返回上一层，等同 `Esc`。
- **时间线**：列表上方的时间线拖动后立即按这段时间筛选，单击只选中一格，再点一次同一格查看。概览的时间线拖动或单击只选中，再点一次选中处或按 `Enter` 查看这段时间的请求。

鼠标开启时，多数终端需要按住 `Shift` 才能用鼠标选取文字。按 `M` 关闭鼠标操作，把鼠标还给终端，再按一次重新开启；这个设置在切换会话后保留。

在列表或详情中按 `e` 导出选中请求的证据压缩包，默认保存到当前目录的 `evidence-<ID>.zip`。导出需要采集锁，采集进行中会提示先停止采集，目标文件已存在时不覆盖。

| 按键 | 操作 |
| --- | --- |
| `1` / `2` / `3` / `4` | 切换概览、请求、告警、健康，各页记住自己的光标 |
| `s` | 返回会话选择页 |
| `↑` / `↓` 或 `j` / `k` | 在列表中选择请求；在详情中 `j` / `k` 查看下一条 / 上一条，`↑` / `↓` 滚动 |
| `g` / `G` | 回到最新并恢复跟随 / 本页末尾 |
| `n` / `p`、`←` / `→`、`PgDn` / `PgUp` | 列表翻页 |
| `Enter` | 打开请求详情，或在概览区块、告警聚合行上下钻 |
| `[` / `]` 或 `Tab` / `Shift+Tab` | 切换请求/响应、参数、解码、解压正文、检测依据 |
| `d` / `f` / `i` | 详情中打开解码工具 / 切换 JSON 格式化 / 展开记录信息 |
| `L` / `<` / `>` | 详情中切换请求与响应排版（左右、上下、单独）/ 调整列表与详情宽度 |
| `t` | 列表中进入时间线选择时间范围 |
| `c` / `m` / `H` / `S` | 只看选中请求的来源 / 命中规则 / Host / 服务（服务在详情中），再按一次取消 |
| `x` | 清空全部筛选 |
| `/` | 打开筛选面板，`Tab` 或 `↑` / `↓` 换行，`←` / `→` 切换选项，`Enter` 应用，`Ctrl+R` 清空 |
| `e` / `y` / `Y` | 导出选中请求的证据 / 复制请求 ID / 复制详情当前标签内容 |
| `/`（详情内）、`n` / `N` | 在当前标签中查找，跳到下一处 / 上一处 |
| 空格 / `r` | 暂停或恢复自动刷新 / 立即刷新 |
| `z` | 切换本地时间与 UTC |
| `A` | 打开分析面板 |
| `Tab` / `Shift+Tab`（概览） | 切换时间线、命中规则、来源地址、告警级别、响应状态、最近告警区块 |
| `←` / `→`、`Shift+←` / `Shift+→`（时间线） | 移动 / 选择时间范围，`Enter` 查看这段请求 |
| `v` | 告警页切换逐条、按规则、按来源视图 |
| `Esc` | 关闭弹层、清除详情查找、关闭详情，或从下钻结果返回原页面 |
| `M` | 关闭或开启鼠标操作 |
| `?` | 打开快捷键帮助；终端较矮时用 `↑` / `↓`、`PgUp` / `PgDn` 或滚轮翻看 |
| `q` / `Ctrl+C` | 退出 TUI |

默认每秒自动刷新，历史页保持当前浏览位置，打开的详情会更新后续到达的响应。暂停刷新后仍可手动刷新和查询。宽度达到 120 列时详情与列表分栏，窄终端使用独立详情页。建议至少 80 列、24 行，时间按标签栏标注的时区显示。

分析程序以只读方式打开现有 SQLite 索引，证据导出写入指定的新 ZIP 文件，分析面板只写入新的分析代次。采集心跳超过五秒未更新时提示心跳过期，状态文件缺失时仍可浏览 SQLite 中的请求。运行用户需要会话目录和文件的读取权限，普通查询和界面浏览无需管理员权限。

### 浏览器界面

```bash
./bin/traffic-console web --session ./sessions/incident-001
./bin/traffic-console web --data-dir /var/lib/traffic/sessions --listen 127.0.0.1:9000
```

启动后 stderr 会打印带访问令牌的地址，直接打开即可。默认只监听回环，远程分析建议用 `ssh -L 8080:127.0.0.1:8080 user@host` 转发；`--allow-remote` 会让令牌和正文以明文过网，只用于隔离网络。

页面分为会话选择、概览、请求和告警四部分。左上角可收起或展开会话导航，浏览器会记住这个设置。地址栏记录当前会话、标签、筛选条件和打开的记录，刷新、后退和复制地址都会回到同一视图。

- **会话选择**按日期分组，显示状态、主机、请求数和告警数，可按名称、主机或目录查找。
- **概览**显示累计计数、数据缺口提示、请求与告警时间线、命中规则、来源地址、告警级别和响应状态分布、最近告警以及采集状态。点击规则、来源或分布项会跳到对应的筛选结果，在时间线上拖选会把列表限定到这段时间。
- **请求 / 告警列表**每页 100 条，支持 Host/URL 关键词、级别、响应状态、请求方法、来源地址、规则、服务和起止时间组合筛选，输入后即时生效。关键词默认匹配原文；旁边的下拉框可改为「URL 解码 1 次 / 2 次 / 3 次后匹配」，用于查找 `%2520` 这类多重编码的载荷，排除关键词同样按此方式匹配。「隐藏静态资源」去掉 js、css、图片、字体等请求；「更多条件」中可填排除关键词（空格或逗号分隔）、包含参数（按参数名匹配，如 `cmd` 不会命中 `xcmd`）以及精确状态码（如 `403`）。列表上方的时间线随筛选条件变化，同样可以拖选缩小范围。翻到历史页时保持当前位置，并提示新到达的请求数。
- **详情**打开时直接显示报文。详情区足够宽时，「请求/响应」标签并排显示两侧报文；窄屏通过「请求」「响应」标签切换。点击「展开记录信息」可查看方法、状态、原始 URL、时间、来源、Host 和服务等字段，再次点击可收起。查询参数可在原始 URL 和解码来源中查看。请求内容会标出规则命中的片段，JSON 正文可格式化显示。gzip 请求和响应正文在「解压正文」中查看。
- **解码**标签是手动的逐步解码工具：从下拉框选择来源（完整 URL、路径、各查询参数、Cookie、表单参数、请求正文、常见请求头），或点击参数旁的「解码」、URL 旁的「解码」、命中片段下的「解码片段」，也可以选中任意文字后按 `d`。可用的解码有 URL、URL（保留 +）、Base64（含 URL 安全变体）、Hex、HTML 实体、Unicode / JS 转义（`\uXXXX`、`%uXXXX`、`\xHH` 等）、JWT（只解头部和载荷，不校验签名）、Gzip / Deflate 解压。每一步都在上一步结果上继续，例如「URL → URL → Base64」，步骤条上可点回任一步或撤销；能对当前结果生效的解码按钮会高亮。二进制结果可切换十六进制显示。解码只在浏览器中进行，不改动采集数据。来源、Host、服务和规则可以直接点击作为筛选条件。复制按钮旁的「导出证据」下载与 `traffic-console export` 相同的 ZIP，采集进行中时导出会被拒绝。

采集中的会话按 `--refresh` 间隔自动刷新，默认每秒一次，最小 500 毫秒。已结束的会话降为每 5 秒检查一次，时间线和统计的刷新间隔不低于 5 秒。索引较大时，响应状态分布超过 1.5 秒会被跳过并在页面上说明。右上角可以切换本地时间与 UTC、深色与浅色配色，详情栏宽度可拖动调整。

| 按键 | 操作 |
| --- | --- |
| `1` / `2` / `3` | 切换概览、请求、告警 |
| `j` / `k` 或 `↓` / `↑` | 下一条、上一条请求 |
| `g` / `G` | 本页第一条、最后一条 |
| `n` / `p` | 下一页、上一页 |
| `[` / `]` | 切换详情标签 |
| `/` | 聚焦搜索框 |
| 空格 / `r` | 暂停或恢复自动刷新 / 立即刷新 |
| `Esc` | 关闭详情或离开输入框 |
| `?` | 打开快捷键帮助 |

### 命令行查询

```bash
./bin/traffic-console status   --session SESSION
./bin/traffic-console requests --session SESSION --limit 100
./bin/traffic-console requests --session SESSION --client 192.0.2.10 --rule SQLI-001
./bin/traffic-console events   --session SESSION --severity high
./bin/traffic-console show EVENT_ID --session SESSION
./bin/traffic-console export EVENT_ID --session SESSION --out ./evidence.zip
```

筛选参数：`--since`（RFC3339）、`--client`、`--rule`、`--severity`、`--service`、`--limit`。TUI/Web 另有 Host/URL 关键词。`show` 含可读正文和 base64 字节；原始网络字节在 PCAP 里。采集中不能导出，先停止采集。分析程序以只读方式打开索引，运行用户需要会话目录和文件的读取权限，普通查询不需要 root。

## 停止、回滚与清理

| 场景 | 操作 |
| --- | --- |
| 正常结束采集 | `Ctrl+C`，等待摘要写出 |
| 定时结束 | 启动时加 `--duration 10m` |
| 预加载回滚 | 只移除本工具对应的预加载条目，再重启目标服务；保留其他库条目 |
| 确认库已卸载 | `grep libtraffic /proc/PID/maps` 应无输出 |
| 删除测试产物 | 直接删除会话目录；证据 ZIP 与会话目录分开保存 |
| Web 令牌失效 | 重启 `traffic-console web`，或用 `TRAFFIC_WEB_TOKEN` 固定 |

采集程序不会自动注册系统服务或修改站点配置。动态探针须按后端显式启用；预加载须在目标进程启动时加载。实验环境搭建脚本会创建相应测试服务，勿与采集命令混淆。

### 从旧版本升级

- `traffic tui` 改为独立程序 `traffic-console`。
- `traffic status/requests/events/show/export` 改为 `traffic-console ...`。
- 原来的 `traffic analyze` 改名为 `traffic import`，用于离线 PCAP。
- 会话格式保持兼容：分析器可读旧版平铺目录和新版分层目录，证据导出同样支持。

## 参数速查

### 采集器 `traffic capture`

| 参数 | 默认 | 用途 |
| --- | --- | --- |
| `--interfaces` | Linux `any` | 网卡列表，逗号分隔 |
| `--ports` | `80,443` | 抓包与 TLS 事件的本地端口 |
| `--service` | `auto` | `auto` / `nginx` / `apache` / `tomcat` / `openssl` / `iis` |
| `--pid` | 0 | 限定目标进程 |
| `--ecapture` | `/opt/traffic/bin/ecapture` | eCapture 路径 |
| `--libssl` | 自动发现 | 指定 TLS 库，排错时很有用 |
| `--no-tls` | 关 | 只保存网络包，不启动 TLS 探针 |
| `--openssl-preload-socket` | 空 | 启用预加载后端 |
| `--openssl-preload-allow-uid` | 空 | 允许非 root 服务账号写入 |
| `--trusted-proxies` | 空 | 保存可信代理 IP/CIDR，供本地还原来源使用 |
| `--output` | 自动 | 精确会话目录 |
| `--data-dir` | `./sessions` | 自动命名会话的根目录 |
| `--name` | `capture` | 会话名 |
| `--duration` | 0 | 到时自动停止 |
| `--disk-limit-mib` | 2048 | 会话磁盘预算 |
| `--pcap-buffer-mib` | 32 | 每个 libpcap 接口的内核抓包缓冲，范围 2–1024；内核拒绝时回退 libpcap 默认值并记录 `pcap/capture_buffer_fallback` 缺口。WinDivert 不使用 |
| `--no-detect` | 兼容参数 | 采集始终不执行检测 |
| `--require-tls` | 关 | 所选目标未通过 HTTPS 预检时拒绝开始 |
| `--collector-memory-mib` / `--collector-cpu-percent` | 256 / 50 | 限制采集器及子进程，不含目标内探针。会话目录若在 tmpfs/ramfs（如多数发行版的 `/tmp`、`/dev/shm`），证据计入该内存预算且无法回收；此时 `--disk-limit-mib` 超过内存预算一半会在开始前拒绝采集，请改用磁盘目录 |
| `--drain-timeout` | 5s | 部分后端的数据排空预算，最大 15s |
| `--stop-timeout` | 30s | 停止后的总等待预算，不小于 `--drain-timeout`；超时记录 `stop_budget_exceeded` 缺口、标记失败及排空未确认，以非零状态退出 |
| `--netns-pid` | 0 | Linux 显式选择抓包网络命名空间 |

`traffic capture --help`、`traffic doctor`、`traffic-console rules check FILE` 可随时查看。`doctor` 默认显示中文自检报告，网卡掩码转为 CIDR；自动化读取请使用 `traffic doctor --json`，原始 JSON 字段保持兼容。分析器用 `traffic-console --help` / `--cn-help` 查看总览，`traffic-console web --cn-help`、`analyze --cn-help`、`rules --cn-help` 查看各命令的中文参数和示例；`--help` 为英文帮助。

## 会话目录与完整性

```text
sessions/web-01/2026-11-11/15-04-05-nginx/
├── manifest.json     # 主机、名称、过滤条件、布局版本
├── status.json       # 心跳、计数、丢弃、错误、资源限制
├── gaps.jsonl        # 带原因、后端、连接和单位的已知缺口
├── analysis-current.json # 本地分析成功后创建的结果指针
├── analysis-*.sqlite  # 本地还原、索引、告警及规则快照
├── capture.lock
├── packets/          # 顺序分段 PCAP（HTTPS 仍是密文）
├── tls/stream.jsonl   # 原始探针事件 JSONL（按需创建）
└── logs/             # 探针诊断
```

采集器只保存原始数据，不执行还原、配对和索引。PCAP 每段约 64 MiB，顺序保留，不循环覆盖；达到磁盘预算或剩余空间低于 512 MiB 时停止。磁盘检查存在间隔，可能略超预算。探针仍有单事件及队列上限，零丢弃不证明采全。停止采集后复制整个目录；旧会话还需保留 `index.sqlite-wal`/`-shm`。判断完整性看 `status.json`：

- `gap_counts` / `gaps.jsonl`：按后端、原因和计量单位保存已知缺口；`drain_state` 和 `probe_exits` 分别报告排空及退出确认。常见原因：`ecapture/receive_queue_shed`（接收队列过载时丢弃的探针消息，传输继续）、`pcap/write_queue_overflow`（磁盘跟不上时丢弃的网络包）、`collector/stop_budget_exceeded`（停止超过 `--stop-timeout`）。
- `tls`：`attached` / `active-preload` / `partial` / `unavailable` / `disabled`。
- `tls_dropped`、`queue_dropped`、`dropped`：已观测丢弃，是下限。
- 原始采集阶段 `transactions`、`alerts`、`tls_requests` 不表示业务请求数量；还原计数和完整性来自本地分析报告。
- `tls_coverage=unverified`、`tls_missing_estimate=null`：启动窗口和探针盲区未知，需要外部请求计数核对。

## 故障排查

| 症状 | 常见原因 | 处理 |
| --- | --- | --- |
| `doctor --json` 报 `ecapture_installed: false` | 未构建或路径不对 | 跑 `scripts/build-ecapture.sh`，或用 `--ecapture` 指定 |
| 抓不到任何请求 | 网卡或端口不对 | `ip -br addr` 选接口；确认 `--ports` 含实际监听端口 |
| 只有密文、`tls=unavailable` | 未发现服务、库路径错、后端不支持 | 看 `doctor` 的 targets；指定 `--service` / `--pid` / `--libssl` |
| nginx 采集到了但部分请求缺失 | 附加前已进入的调用、HTTP/2、突发缺口 | 用预加载路径或降低速率；完整性按 `unverified` 处理 |
| 预加载无事件 | 服务未重启、targets 不匹配、socket 权限 | 重启 master；检查 `/etc/traffic/openssl-preload.conf`、`ls -l /run/...`、`--openssl-preload-allow-uid` |
| 预加载报 `bind: no such file or directory` | 父目录不存在（旧版本） | 升级到当前版本，或先 `mkdir -p /run/traffic` |
| `permission denied` 打开 BPF | 非 root 或缺少权限 | 用 `sudo`；容器内需要相应 capability |
| TUI 找不到会话 | 工作目录或路径不对 | `--session` 指向会话目录；`o` 输入其他根目录 |
| 导出失败 | 采集仍在运行，或目标 ZIP 已存在 | 先停止采集，换一个新的输出路径 |
| 时间对不上 | 采集机时钟/时区 | 会话存 UTC，TUI 默认按本地时区显示，`z` 切换 UTC；先校时再采 |
| Web 打不开 | 监听地址或令牌 | 用启动时打印的完整地址；远程用 SSH 转发 |

## 检测规则

### Web 规则文件管理

启动 `traffic-console web` 后，点击侧边栏的「会话规则」（地址 `#/rules`，每个文件有独立地址 `#/rules/文件名`，可直接收藏或分享）。左侧选择文件，中间编辑 YAML，右侧显示解析出的规则；支持新建、导入 UTF-8 文件、校验、保存（<kbd>Ctrl</kbd>+<kbd>S</kbd>）、下载及删除。输入时自动校验，点击解析结果中的规则可定位到编辑器对应位置。内置规则只读。保存前校验规则 ID、字段、级别和正则，校验失败不会覆盖文件；文件版本冲突时需重新打开，避免覆盖其他窗口的修改。有未保存修改时离开页面会先确认。

规则页右侧有两个标签，共用右上角的「参照会话」：

- **规则**：解析出的规则加上它在参照会话中的命中请求数和最近命中时间，点击命中数直接打开对应告警。如果会话上次分析没有用到这条规则，显示「未参与分析」；如果规则在分析之后被改过（正则、字段、级别或版本不同），显示「已修改，需重新分析」，不会给出误导的 0。
- **测试**：用编辑器里的内容（无需保存）加内置规则检测一条样本，只读，不改动会话。样本可以从参照会话中点选一条请求（支持按 Host/URL 搜索、仅看告警），也可以手动粘贴请求和可选的响应报文。结果逐条列出本文件规则是否命中、命中字段、解码轮次和匹配片段，并对照该请求已保存的告警标出「本次新增」「本次未命中」。选定样本后，每次修改规则都会自动重新测试。

默认目录为程序旁的 `rules/`，从源码构建到 `bin/` 时使用项目根目录的 `rules/`。Web 启动时自动创建目录，与当前工作目录无关；用 `--rules-dir` 可覆盖默认位置。单文件最多 1 MiB，最多 256 个文件，不接受目录穿越或符号链接文件。

```bash
./traffic-console web --data-dir ./sessions --rules-dir ./rules
```

打开会话后点击顶栏的「分析」，选择「仅内置规则」或「内置 + 文件名」，再点击「开始分析」。也可以在规则页点击「用此规则分析」，进入参照会话并带入这份规则。关闭弹窗后任务继续运行，「分析」按钮上的圆点表示当前会话有任务进行中。重新打开弹窗可查看任务进度、停止分析及查看该会话在本次服务运行期间的近期任务。每次使用启动时的规则快照，修改或删除文件不改变正在运行的任务或已有结果。任务完成后，页面自动刷新告警；同一 Web 服务一次只运行一个分析任务，服务退出时取消未完成任务。Web 分析不触发 Webhook。

### 命令行分析与规则格式

当前源码已将 TCP/HTTP 还原、请求响应配对、索引及检测移到本地分析器（尚未发布；v0.1.2 包仍采用旧流程）。`capture` 和 `import` 只保存原始流量；先停止采集，再执行 `traffic-console analyze --session DIR`。新原始会话在分析前没有可查询的请求表，Web 可在打开会话后通过「分析」按钮启动任务。

每次分析从原始 PCAP 和 `tls/stream.jsonl` 重建事务，再按采集时间执行内置及本次追加的规则。结果存入不可变的 `analysis-*.sqlite`，包括本地还原正文、索引、告警、规则内容/指纹和完成时间；`analysis-current.json` 原子切换当前结果。原始流量和状态文件保持只读，失败或取消保留上次完整结果。构建中的结果库是会话目录内隐藏的 `.analysis-build-*.sqlite`，成功后改名为新的 `analysis-*.sqlite`；异常退出遗留的构建文件在之后一次成功分析时清理超过一天的部分。每次成功分析后只保留当前和上一个 `analysis-*.sqlite`，更早的结果库随即删除，反复重新分析时会话目录最多占用两份结果库；已打开旧结果的终端或 Web 会话继续读取原内容，Windows 上仍被打开的旧结果库在之后一次分析时再删除。分析引擎 v5 起，列表、筛选与统计所需字段单独成列，不再逐条解析含正文的 JSON；更早版本的分析结果仍可直接查看，重新分析后获得同样的查询速度。旧版 `index.sqlite` 会话继续使用原索引，支持本地规则重算。

TUI、Web、JSON 查询及导出读取同一代分析结果；Web 和 TUI 每次刷新读取最新结果。源文件大小或修改时间变化会使结果失效，需重新分析；这项快速检查不代替证据哈希校验。导出包含 `analysis.json`，原始会话另含 `reconstructed-event.json`，旧会话使用 `captured-event.json` 区分原索引记录。

`traffic-console analyze --request-limit BYTES --response-limit BYTES` 控制本地正文还原和检测上限，默认每侧 1 MiB，最大 16 MiB；Web 使用默认值。上限造成的本地截断可通过调大后重新分析恢复，采集缺口则无法补回。构建结果库所需空间与采集证据大小相当，空间不足时报告会话目录所在磁盘已满。`--retention` 已从采集器删除，旧版循环 PCAP 曾被覆盖的内容无法恢复。

内置规则覆盖疑似 SQL 注入、命令注入、路径穿越、敏感文件探测、扫描、XSS、SSRF、XXE、SSTI、JNDI、反序列化、Webshell 上传，以及响应中的 passwd / 命令输出特征。命令注入（CMD-001）要求分隔符后的命令再跟空白、结尾或 shell 元字符，因此与命令同名的普通参数（如 `&id=5`、`&cat=3`）不会触发。原始内容和最多两轮 URL 解码视图参与匹配，gzip 正文有界解压。告警是疑似信号，结论要结合响应和现场证据。

```yaml
- id: CUSTOM-001
  version: 1
  severity: medium
  field: url
  pattern: '(?i)/suspicious-endpoint'
```

```bash
./bin/traffic-console rules check rules.yaml
./bin/traffic-console analyze --session ./sessions/incident-002 --rules rules.yaml
```

`field` 支持 `url`、`request`、`response`、`request.headers`、`response.headers`、`request.body`、`response.body`，单个头部用 `request.header.User-Agent` 这类写法。`severity` 为 `low` / `medium` / `high`。扫描检测默认 60 秒内至少 20 个不同路径且一半以上为 404，在 `traffic-console analyze` 中用 `--scan-window`、`--scan-paths` 调整。扫描检测同时最多跟踪 2,000 个客户端、每个客户端 1,000 个路径；超出部分的事务不参与统计，其中的扫描可能未报出。达到上限时，分析结果的 `scan_skipped` 记录这类事务的条数，`analyze` 命令、终端和 Web 的分析面板会给出提示。

### 可信代理与来源地址

```bash
--trusted-proxies 10.0.0.0/8,192.0.2.10,2001:db8::/32
```

直连对端可信时，从右向左解析 `X-Forwarded-For` 的第一个非可信地址；没有该头时用单值 `X-Real-IP`。索引和告警用解析后的 `client`，`peer_client` 保留直连端点，`client_source` 记录依据。代理头不带端口，解析后端口记为 `0`。

### 告警外送

`traffic-console analyze --alert-webhook URL` 在分析成功后异步 POST 告警 JSON，`TRAFFIC_WEBHOOK_TOKEN` 发送 Bearer 令牌，接收端可用 `Idempotency-Key` 去重。单次超时 3 秒，429/5xx 最多重试三次；队列 128 条、4 MiB，退出最多等 5 秒。投递计数和失败信息在本次 analyze 的 JSON 输出中返回，不写入采集状态；失败或溢出的告警仍保存在本地分析库。重跑并指定 Webhook 会再次发送本次全部告警。

## 资源与证据限制

| 项目 | 默认 |
| --- | --- |
| 请求 / 响应正文 | 256 KiB / 64 KiB，超出标记截断 |
| HTTP 头部 | 32 KiB |
| PCAP | 每接口 64 MiB 分段、16 段循环 |
| 会话磁盘预算 | 2 GiB，达到后停止采集 |
| 低磁盘保护 | 可用空间不足 512 MiB 时停止 |
| 索引保留期 | 24 小时 |
| 进程资源 | Linux cgroup v1/v2 / Windows Job Object，256 MiB、单核 50% |

证据 ZIP 含请求、响应和 SHA-256 清单。有完整传输端点的请求还包含按双端 TCP 地址、端口及请求前后各 60 秒筛选的 PCAP。通过 PCAP 还原的响应晚于默认窗口时，窗口延长至已观测的响应时间。`evidence.json` 记录筛选窗口的起止时间。窗口可能包含同连接上的其他请求或重用同一对端点的流量。最后一段 PCAP 或缺口日志存在残缺记录时，ZIP 保留完整记录并在 `evidence.json` 中列出受影响的源文件。HTTPS 明文来自进程探针，PCAP 保留原始报文字节。明文事件、Cookie 和认证信息可能出现在会话里，分享前先检查。

## Linux HTTPS 依赖与 eCapture

eCapture 以独立子进程运行，仓库固定上游提交 `143e771cf2b4919aedc27fd7b4b24ff87b8725b9` 并应用补丁。当前构建脚本按主机架构生成 ARM64 或 x86_64 的 CO-RE 探针，构建目标含 OpenSSL 1.1.1 四组 ABI 及 3.0、3.5；1.1.1 的完整运行验收仍待完成，包含自定义 BIO 的 socket 关联和 `SSL_read_ex`、`SSL_write_ex` 支持。

```bash
sudo apt-get install -y clang llvm bpftool libelf-dev libssl-dev \
  flex bison make file pkg-config
./scripts/build-ecapture.sh /tmp/traffic-ecapture-build
```

构建目录必须不存在。脚本生成 `bin/ecapture`、许可证、校验文件及 `.traffic.json` 能力清单，部署时保留这些配套文件。补丁修复连接缓存崩溃与 FD 复用的元数据竞争，减少解码复制；TLS 事件使用 100 毫秒时间排序窗口，空闲时也会刷新末批事件。补丁扩展了内部 ABI，探针字节码与用户态解码器必须配套构建。其他 OpenSSL 版本需要单独验证。

## 各后端细节与边界

### 预加载（LD_PRELOAD / ld.so.preload）

库在 `SSL_read`、`SSL_write` 及 `_ex` API 返回后复制实际消费或产生的明文，经有界异步队列发送到 Unix socket；采集器校验内核凭据和 `/proc` 进程启动标识，保存原始明文事件，停采后由 console 还原。该路径可在内核 3.10 上运行。

#### 系统级 `ld.so.preload` 与不同 UID 的服务

`/etc/ld.so.preload` 不能设置环境变量，因此库读取 `/etc/traffic/openssl-preload.conf`，也可用 `TRAFFIC_OPENSSL_CONFIG` 指定：

```ini
socket=/run/traffic/plaintext.sock
targets=nginx,httpd,apache2
# debug_file=/tmp/traffic-preload-debug.log
```

`targets` 是逗号分隔的进程名，支持末尾 `*` 前缀匹配，`*` 表示全部；不匹配的进程保持惰性。采集器用 `--openssl-preload-allow-uid 33` 放行 www-data，socket 为 `0660` 并归属该 UID 的主组，新建的父目录会设置为可穿越；已有父目录权限保持不变，需要操作者为服务账号配置访问权限。

`ld.so.preload` 只影响之后 `exec` 的进程：`nginx -s reload` 不会重新加载 master 的库，必须重启 master。worker 由 master fork，master 启动时载入后即覆盖 worker。回滚时只移除本工具对应的库条目并重启服务，确认 `/proc/PID/maps` 不再包含该库。`debug_file` 每次进程首次初始化写一行，默认关闭。

队列最多 128 条事件，单条约 19 KiB，采用有界原子预留与独立后台消费。连接元数据分为 64 个分片，每片最多 64 项；满片或争用超过等待预算会报告缺口。发送线程有界重试，恢复时先发送缺口标记再发送后续正文。可上报缺口计入 `tls_dropped`；进程崩溃、`_exit`、采集器停机和最后未送出的事件仍是未知缺口。Linux cgroup v1/v2 在控制器可用且有权限时限制采集器，实际结果见 `resource_limits`，不改变目标服务的 cgroup。已测动态 OpenSSL 1.0.2k / TLS 1.2，以及 Debian 13 / OpenSSL 3.5 / nginx 1.26 的系统级预加载、TLS 1.2/1.3 和非 root worker；静态链接、绕过符号拦截、自定义无 socket BIO、Go TLS、HTTP/2 和长期性能未验证。

### Apache

自动发现 `apache2` / `httpd`，采集 OpenSSL HTTPS 明文。worker/prefork 在采集开始前已经阻塞在 `SSL_read` 的调用，首次返回可能漏采，后续调用和新连接正常。`scripts/verify-services.py` 可对已运行服务做串行验收。

### Tomcat / Java Agent

显式 `--java-attach` 才附加，支持 Tomcat 9/JDK 17、Tomcat 10.1/JDK 21 的 NIO Connector。Agent 用一条发送线程和 128 个分片槽位，单片 64 KiB，队列正文最多 8 MiB；溢出会标记缺口。停止后通道关闭、Agent 停用并恢复字节码，同一 JVM 可再次附加，但 Agent 不支持在同一 JVM 内热升级。禁止附加的 JVM 会报失败，网卡采集继续。

### 通用 OpenSSL

`--service openssl --pid N` 适用于使用 OpenSSL 的其他程序。已用 HAProxy 和外部 `SSL_read_ex` / `SSL_write_ex` 调用验证；OpenSSL 3.0 `s_server -www` 的内置 BIO 路径实测未取得明文，自定义 BIO 目前适配 Apache。

## Windows 采集

从源码构建需要 Go 1.26.7+ 和 x64 MinGW GCC；正式发行包已包含 WinDivert、Python、Frida 和探针，无需安装 Npcap。

```powershell
powershell -ExecutionPolicy Bypass -File scripts/windows/build.ps1
.\bin\windows\traffic.exe doctor
.\bin\windows\traffic.exe capture --no-tls --ports 8080,8443 --duration 60s --name windows-http
```

完整发行包默认使用 WinDivert 覆盖本机接口和回环；也可用 `doctor` 返回的 `windivert:接口索引` 或系统接口名。旧的 Npcap 回退仅适用于自行构建。抓包快照上限 256 KiB，避免回环大帧截断。证据目录使用继承 ACL；Job Object 限制 256 MiB 内存和单核 50% CPU。

### IIS

```powershell
# 完整发行包已包含 Python / Frida；在管理员 PowerShell 运行
.\traffic.exe doctor --service iis
.\traffic.exe capture --service iis --ports 8080,8443 --duration 60s
```

IIS 探针动态附加 `w3wp.exe`，在 HTTP Server API 收发边界复制明文，无需安装模块或回收应用池。`probe-runtime` 目录必须允许目标应用池身份读取。当前源码在完成通知、正文读取及响应发送时，从有界的完成上下文中识别原始 `HTTP_REQUEST`，按请求 ID、TLS、端口及结构字段校验并去重，恢复附加前已投递、附加后才完成的接收。不会重发或消费业务请求，不再要求用预热流量绕过前十条遗漏。

- `probe_receive_matches` 是已登记的接收完成数；`probe_recovered_receives` 是恢复的请求数，分别报告，不代表漏采估计。
- `plaintext_observed=true` 表示请求侧原始事件已记录。这不代表正文、还原及配对全部成功，仍需停采后由 console 分析并按客户端账本核对。
- 附加前已完成的请求、无法识别的完成上下文、内核缓存和未覆盖 API 路径仍不保证采集。`tls_coverage=unverified` 与零丢弃不能作为采全证据。
- `attach_window_suspect` 只有满足特定诊断条件才置位，false 不能排除启动缺口。未匹配完成通知包含其它 I/O，不能换算成遗漏请求数。

`--require-plaintext` 在未附加 IIS 或未记录任何请求侧原始事件时以非 0 退出；写入/排空失败也会使采集失败。它不要求采集端进行 HTTP 还原。`--require-tls` 只检查附加前的预检，不保证采到明文。停止时可能因未完成 I/O 导致运行时未完全卸载。实测范围是 Windows 10 17763 与 19044、HTTP/1.1、TLS 1.2。

### Windows nginx / apache / 通用 OpenSSL

```powershell
.\traffic.exe capture --service nginx --ports 80,443
.\traffic.exe capture --service apache --ports 80,443
.\traffic.exe capture --service openssl --pid 1234 --ports 9443 --libssl libssl-3-x64.dll
```

Windows nginx 探针优先检查 OpenSSL 导出符号。没有导出符号的静态构建通过 profile 匹配 `nginx.exe` 的架构、SHA-256 和函数入口。内置 profile 支持以下构建：

- Windows x86（32 位）为 nginx.org 的 1.27.4 和 1.28.0。
- Windows x86-64（64 位）为 [iliweii/nginx-rtmp-win64 的 1.28.1 构建](https://github.com/iliweii/nginx-rtmp-win64/tree/8e9a9c842da0edff6d5ab36069e478cbfef8c2f7)。

其他无导出符号的静态构建需要提供匹配的 `--openssl-profile`。使用 `--service nginx` 时，进程的可执行文件名应为 `nginx.exe`。辅助脚本目录需同时保留 `probe-openssl.py`、`probe-iis.py`、`openssl-plaintext.js` 和 `openssl-profiles.json`。动态附加只覆盖附加后进入的调用，附加前已阻塞的读取和半截消息可能漏采。Windows 的完整验收脚本为 `scripts/windows/verify-iis.py` 和 `scripts/windows/verify-middleware.py`。

- nginx 探针就绪后目标显示 `attached`。没有可用探针时查看 `tls=unavailable` 和 `probe_unavailable` 缺口。`plaintext_observed=true` 表示至少一条非空 nginx TLS 明文事件已进入证据队列。请求数以 console 重建结果为准。
- worker 退出时，helper 会转发已收到的尾部事件。可量化的宿主队列丢弃以消息数和有效载荷字节数记录为 `probe_queue_loss`。没有最终序列确认时，每次退出记录一条 `drain_unconfirmed/shutdowns`，进程内及传输中的剩余事件和字节数未知。

## 构建（分平台）

```bash
# Linux：竞态测试、go vet、两个程序与校验文件
./scripts/build-linux.sh

# 也可以分别构建
go build -o bin/traffic ./cmd/traffic
go build -o bin/traffic-console ./cmd/traffic-console
```

分析程序可在 Linux、macOS 或 Windows 构建；Linux eBPF 和 Windows IIS 后端必须运行在对应目标系统。构建出的采集器、分析器和 eCapture 必须同架构。

## 验证范围

| 平台或服务 | 能力 | 实机边界 |
| --- | --- | --- |
| Linux ARM64 / x86_64 HTTP | 网卡抓包、HTTP/1.1 重组、循环 PCAP | 支持分段、乱序、重传、长连接、中文、分块 |
| Linux nginx / OpenSSL | 运行中采集 HTTPS 明文、客户端端点、进程身份 | ARM64/x86_64 的 TLS 1.2/1.3 通过 |
| Linux Apache | 自动发现并采集 OpenSSL 明文 | ARM64 event/worker/prefork 已测，阻塞读取有首次漏采边界 |
| Linux Tomcat / JSSE | 动态附加 Java Agent | Tomcat 9/JDK 17、10.1/JDK 21 NIO 已测 |
| Linux 通用 OpenSSL | 指定 PID 采集 | HAProxy、外部 `_ex` 调用已测 |
| Linux 预加载 | `LD_PRELOAD` / `ld.so.preload` | CentOS 7 / OpenSSL 1.0.2k；Debian 13 / OpenSSL 3.5 / nginx 非 root worker 已测 |
| Windows IIS 10 | Npcap HTTP + 动态 HTTPS | 17763、HTTP/1.1、TLS 1.2 已测 |
| Windows nginx / apache | Npcap HTTP + OpenSSL 探针 | nginx 1.28、Apache 2.4.71 的 TLS 1.2/1.3 正文比对通过 |
| Windows 通用 OpenSSL | 指定 PID | 外部 `_ex` 调用通过，内置 BIO 路径未取得明文 |

完整实机数据和证据位置见 [验证记录](../VALIDATION.md)。

### 已知限制

- HTTP/2 已实现有界帧、HPACK 和多路复用解析，完整后端实机矩阵未验收；中途附加缺少 HPACK 历史时保留证据并停止不可靠解码。HTTP/3、WebSocket 内容解析、通用 JSSE/Go TLS、Tomcat NIO2 尚未支持；HTTP/1.1 流缺失消息开头时恢复受限。
- 持续高负载仍有 eCapture 接收预算耗尽及后端不可用的失败样本；正式低影响门槛、八小时长压和各后端端到端排空尚未完成。
- Windows 其他 Web 服务、IIS TLS 1.3、内核缓存直接命中、应用池替换、长期性能和 Frida 完整卸载未验收；IIS 启动窗口可能漏采。
- Linux x86_64 的 Apache、Tomcat、通用 OpenSSL 和长期性能仍待单独验收。
- 代理来源地址依赖可信代理配置和正确的转发头，默认使用连接对端。
- Web 界面已覆盖令牌、筛选、详情和导出测试，真实网卡到浏览器的完整链路仍待实机验收。

## 测试

```bash
go test -race ./...
go vet ./...
```

CI 在 ARM64 / x86_64 Linux 执行格式检查、竞态测试、静态检查和构建，Windows x64 执行原生测试与构建，Java 17/21 执行 Maven 测试与打包。PCAP/PCAPNG 离线导入使用纯 Go 读取器，支持 Linux SLL2，并按 PCAPNG 接口分别保存分段。Windows 无需 Npcap 即可运行离线集成测试；发布流程另验证随包 WinDivert 的回环 HTTP 实际采集。

实机脚本需要兼容的测试站接口（`/api/health`、`/api/echo`、`/search`、未知路径 404），串行发送请求，输出目录必须为新目录：

```bash
python3 scripts/verify.py /tmp/traffic-functional --host 127.0.0.1
python3 scripts/benchmark.py --output /tmp/traffic-performance --host 127.0.0.1
```

脚本支持 `--binary` 和 `--config` 指定采集程序与 Nginx 配置。功能脚本另通过 `--analysis-binary` 指定证据导出所用的 `traffic-console`，默认路径为 `/opt/traffic/bin/traffic-console`。可用 `--ecapture` 指定探针路径、`--pid` 将 TLS 探针限定到实验进程。功能脚本检查 126 条请求及响应、已有 HTTPS 连接、TLS 版本、中文正文、五类规则、网站配置和 PID、证据校验。性能脚本默认 20/100 请求每秒、每组五分钟、重复三轮。

## 第三方组件

依赖及版本见 `go.mod`、`go.sum`。eCapture 以独立子进程运行，固定源码、补丁和构建方式随仓库提供。版权与许可证说明见 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。
