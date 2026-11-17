# 2026-11-17 边界修复与原始采集迁移（当前源码，未发布）

## 修复范围

| 原问题 | 当前行为 | 验证 |
| --- | --- | --- |
| 会话内 analysis.sqlite 符号链接可引导写入外部数据库 | 私有临时目录构建；拒绝已有分析路径符号链接；通过 os.Root 独占创建随机结果代次和原子指针发布 | TestAnalysisRejectsSessionSymlink；外部文件内容不变 |
| 外部重算后 Web 缓存混用旧计数/规则与新告警 | 每次请求独立读取不可变分析代次，计数、正文和规则元数据来自同一连接；TUI 刷新读取新结果 | TestExternalReanalysisPublishesConsistentProvenance；旧 reader 代次固定测试 |
| 导入异步持久化失败仍返回完成 | 导入检查 fatal；PCAP 尾部 Flush/Sync/Close 错误记入 fatal；失败以非零状态退出 | evidence writer 写入、Sync、Close 失败回归；CLI 磁盘失败验收 |
| 离线导入绕过磁盘预算及剩余空间检查 | 开始、周期和结束检查；检查目录失败也返回错误 | 68 MiB 输入、64 MiB 预算：退出 1，status.state=failed |
| cancel 请求读 body 时持有 jobMu，可阻塞状态接口 | 先有界解码再持锁；body 读超时 15s；HTTP 配置 ReadTimeout/IdleTimeout | TestSlowCancelDoesNotBlockJobControl |

## 采集与分析边界

- `traffic capture/import` 保存网络 PCAP、`tls/stream.jsonl` 原始明文/API 事件及目标/缺口/退出元数据。采集器没有 TCP assembler、HTTP 解析、配对或 SQLite 索引，依赖图没有 sqlite、tcpassembly、internal/replay、internal/index。
- v3 manifest 使用 `capture_mode=raw`；PCAP 约 64 MiB 顺序分段，不再循环覆盖。磁盘预算默认 2 GiB，剩余空间低于 512 MiB 停止；预算检查有间隔，可有少量超出。
- `internal/replay` 由本地 console 调用，负责 PCAP TCP 重组、HTTP/1 与 HTTP/2、TLS 字节流和 IIS API 事件还原、配对与索引，然后匹配规则。保留进程启动身份、服务、后端、采集时间和 loss/end 边界。
- 请求/响应正文上限迁至 `traffic-console analyze`，默认各 1 MiB、最大 16 MiB；提高上限可重新读取原始数据。Web 使用默认值。采集器删除正文上限与 retention 参数。
- 本地分析写入 `analysis-*.sqlite`，通过 `analysis-current.json` 切换；复制过程中支持取消。失败或取消保留旧结果，未发布文件删除。后续发布清理超过一天的旧代次；正在使用的 reader 固定在自己的代次。
- 旧 `index.sqlite` 会话兼容读取和规则重算。新原始会话在分析前仅有采集状态，没有可查询业务请求。
- help、README、guide、资源边界说明、Linux/Windows 验收与打包烟测脚本已同步。历史实机记录不代表本次新架构验收。

## 本轮实测

- macOS arm64：`go test -race ./...`、`go vet ./...` 通过；新增原始会话 Web 后台还原测试单独在 race 下通过。
- Python 9 项单元回归通过；修改的 Python、Shell、JavaScript 语法检查通过；`git diff --check` 通过。
- 本机采集器/console 构建与 Windows amd64 CGO 交叉构建通过。本机链接有 SDK 部署版本警告。
- 独立 CLI：原始 PCAP import 不产生 index.sqlite；console analyze 得到 1 条完整配对事务、2 条告警；requests/export 正常，ZIP 中含 reconstructed-event.json，SHA-256 清单全部通过；manifest/status/PCAP 哈希未变。
- 原始 TLS 大正文回归：默认上限截断；改为 2 MiB 重跑恢复尾部并命中自定义规则，原始明文字节未变。
- 后端归属/身份/loss 边界、IIS API 本地配对、取消发布、20 段 PCAP 不覆盖均有自动化回归。

## 尚未证明的范围

本轮没有执行远端 Linux/Windows TLS 全后端实机、持续高负载或长时间压力验证，没有发布新包，也不宣称已经获得量化的性能提升。移除采集端解析并不保证零丢失：探针单调用上限、队列、附加窗口、TCP 缺包与本地解码资源上限仍存在，已知缺口通过状态/分析报告表达，未知覆盖仍为 unverified。HTTP/3、WebSocket 业务内容、Go TLS 与通用 JSSE 不在当前完整支持范围。
