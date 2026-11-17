# Windows 随包依赖

从 v0.1.2 起，`traffic` 与 `traffic-console` 分开打包。采集器完整 ZIP 已包含运行依赖，不需要 Npcap、在线 pip 或系统 Python。请保留解压目录结构：

```text
traffic.exe
deps/
  windivert/   WinDivert.dll、签名 WinDivert64.sys、许可证及对应源码
  python/      Python 3.13.11 x64 + Frida 17.5.1
  probes/      IIS / OpenSSL 脚本及静态库 profiles
```

在可写目录完整解压，然后打开 PowerShell：

```powershell
.\traffic.exe --cn-help
.\traffic.exe doctor
.\traffic.exe doctor --cn-help
# 以下采集命令需要管理员 PowerShell
.\traffic.exe capture --ports 80,443 --duration 60s
.\traffic.exe capture --service iis --ports 80,443 --duration 10m
.\traffic.exe capture --service openssl --pid 1234 --ports 9443
.\traffic.exe capture --no-tls --ports 8080 --duration 60s
```

`doctor` 枚举系统网络接口并检查依赖，不加载驱动或附加进程。`capture` 使用 WinDivert 的 SNIFF + RECV_ONLY 模式复制网络包，默认覆盖本机接口及回环；驱动在首次采集时自动注册并加载。管理员权限及允许加载签名驱动的系统策略仍是必要条件。驱动不可用时会返回明确错误，不会静默切换为无网络采集。

IIS / OpenSSL 探针默认从随包路径配置，只在采集选中的目标时附加。`--no-tls` 禁用附加。自定义部署仍可用 `--iis-probe`、`--openssl-probe`、`--probe-python`、`--probe-runtime-dir` 覆盖路径。程序自动创建 `runtime/frida`；检测到 IIS 时授予 IIS_IUSRS 对该临时子目录的读取权限，不放宽会话数据目录权限。

依赖路径按 exe 位置解析，不依赖当前工作目录。默认会话位于程序旁 `sessions/`，证据导出位于 `exports/`。分析器可在其他目录，通过 `traffic-console --session 采集会话路径` 打开数据。

WinDivert 不提供每个句柄的队列丢弃计数，采集健康状态会记录 `drop_counter_unavailable`；不能把零丢弃或已附加当作完整性证明。数据包时间采用接收时间。IIS 异步接收、静态 OpenSSL profile、TLS 版本和探针附加窗口的限制仍需按实际目标核对。

二进制与来源校验值见随包 `deps/SOURCES.sha256`。WinDivert 2.2.2 以 LGPLv3 分发，附带完整许可证和对应源码；Python、Frida 原始许可证保留于各自目录。WinDivert 驱动被系统策略阻止时，请保留原始错误与 `doctor` 输出用于排查。
