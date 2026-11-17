# 2026-11-17 三台 Linux 当前源码实机复测

固定源码提交：`c2ee58b8474f416c36bc3caf81eeb228594e7779`。三台机器使用同一个 `git archive` 快照，SHA-256 为 `1d668949bb83f51e9d10ff11beb8f6972b4181fe6ee0b2c68be88486b5175fe3`，并在各自环境用 Go 1.26.11 原生构建采集器、分析器和 OpenSSL 预加载库。本次验证当前源码，不代表 v0.1.2 发行包复验。

## 环境和结果

| 项目 | 192.168.1.7 | 192.168.1.10 | 192.168.1.12 |
| --- | --- | --- | --- |
| 系统 | Debian 13 ARM64 | Ubuntu 26.04 x64 | CentOS 7 x64 |
| 内核 | 6.12.107+deb13-arm64 | 7.0.0-43-generic | 3.10.0-1160.119.1.el7.x86_64 |
| OpenSSL | 3.5.7 | 3.5.5 | 1.0.2k-fips |
| glibc | 2.41 | 2.43 | 2.17 |
| 原生构建、全仓库 race/vet | 通过 | 通过 | 通过 |
| HTTP / eCapture HTTPS 功能链路 | 126 / 126 | 126 / 126 | 未运行，旧内核走预加载路径 |
| OpenSSL 预加载链路 | 19 / 19 | 19 / 19 | 19 / 19 |
| 独立网络命名空间 HTTP 采集 | 1 / 1 | 1 / 1 | 1 / 1 |
| PCAP 导入、离线还原及配对 | 1 / 1 | 1 / 1 | 1 / 1 |
| 原始 eCaptureQ 范围过滤 | 通过 | 通过 | 未运行 |
| Web 鉴权、查询及规则校验 | 通过，126 条事务 | 通过，126 条事务 | 通过，19 条事务 |
| 本轮测试进程清理 | 无残留 | 无残留 | 无残留 |

Debian 默认 `/tmp` 仅余约 483 MiB，首次 `TestImportCreatesOrganizedSession` 触发程序 512 MiB 低磁盘保护；设置 `TMPDIR=/opt/traffic-retest-20261117/tmp` 后，全仓库竞态测试通过。保留首次失败与重跑日志。两台 x64 的竞态测试同样使用独立的 `/opt` 临时目录。

## 功能核对范围

- 两台现代 Linux 的 126 条用例覆盖明文 HTTP、TLS 1.2/1.3、已有 HTTPS 连接、100 条并发/中文 POST、请求响应配对与正文、SQLi/路径穿越/命令注入/敏感文件/扫描五类规则和证据 ZIP SHA-256 校验。原始采集不产生 `index.sqlite`，停止后由 console 本地还原。
- 三台的 19 条预加载用例覆盖长连接、HEAD、中文、128 KiB 回显、并发、请求与响应规则、可信代理、证据 ZIP 校验，以及停止采集后服务继续响应。预加载仅注入本轮新建的独立 Python 测试进程。
- 网络命名空间用例验证目标命名空间内的请求和响应，采集器主线程不切换命名空间；停止采集后测试服务仍可响应。
- 将命名空间采集的 PCAP 再导入新会话，检查采集端无索引，离线分析恢复唯一的 `/netns-proof` 请求及 200 响应，无不完整或截断标记。
- eCapture 原始传输验证 PID、进程启动身份、端口白名单、动态端口替换、空及损坏配置拒绝、合法配置恢复和停止后服务响应。使用已有配套 `ecapture-r38`，本轮没有重编译 eCapture。
- Web 通过实际启动的 console HTTP 服务验证 HTML、无令牌 API 拒绝、会话发现和计数、概览/时间线/请求列表、有效规则通过及无效规则拒绝；本轮没有做浏览器交互验收。

Debian 使用已有实验站，配置和 Nginx PID 均保持不变。Ubuntu 启动独立的回环 Nginx 和 Python 实验站，结束后关闭；没有重启或修改系统服务。CentOS 使用独立的临时 HTTPS 测试服务。三台隔离根目录均为 `/opt/traffic-retest-20261117`。

## 保留边界

全部上述样本无观测 TLS、用户队列或网卡丢弃。两台 eCapture 功能会话各记录 `ecapture/drain_unconfirmed/shutdowns=1`，`data_drained=false`；预加载链路也未确认端到端排空。`drain_state` 和 `tls_coverage` 保持 `unverified`，不能用测试通过或零丢弃计数推导零漏采。

没有执行 HTTP/2 实机、Apache/Tomcat/其他 TLS ABI 全后端矩阵、持续高负载、正式低影响或八小时长压。Ubuntu 的主机时钟与其他机器有偏差，本轮没有调整系统时钟，也没有用跨主机时间戳计算性能。

## 证据

本地 Git 忽略目录 `validation/linux-retest-20261117/<IP>/` 包含各机 `report.json`、`environment.txt`、race/vet 日志、构建产物 SHA-256、功能/预加载/命名空间/导入/Web/清理报告、会话归档和证据 ZIP；总表为 `validation/linux-retest-20261117/summary.json`。原始会话和明文证据不随源码提交。
