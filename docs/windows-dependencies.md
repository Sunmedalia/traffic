# Windows 可选依赖

基础包只含 traffic.exe、traffic-tui.exe 和必要许可证。分析已有会话无需安装抓包驱动。

## 抓包驱动 Npcap

从 [Npcap 官方下载页](https://npcap.com/#download) 下载并以管理员身份安装，选择 WinPcap API-compatible Mode。安装后以管理员身份运行 `traffic.exe doctor` 检查网卡。Npcap 由官方单独分发，本包不包含驱动安装器，也不会自动安装驱动。

## IIS / OpenSSL 明文探针（可选）

将 `traffic-VERSION-windows-amd64-deps.zip` 解压到 traffic.exe 所在目录，得到 deps 目录。包含 Python 3.13.11 x64 便携运行时、Frida 17.5.1、六个运行所需的探针文件及原始许可证，无需安装系统 Python 或在线 pip。源下载地址和固定校验值见 SOURCES.sha256。

在程序目录打开管理员 PowerShell：

```powershell
.\deps\python\python.exe -c "import frida; print(frida.__version__)"
.\traffic.exe doctor
# 使用实际 PID 和端口。runtime 目录需要目标进程身份可读取。
New-Item -ItemType Directory -Force .\probe-runtime | Out-Null
.\traffic.exe capture --service iis --pid 1234 --ports 80,443 `
  --iis-probe .\deps\probes\probe-iis.py `
  --probe-python .\deps\python\python.exe --probe-runtime-dir .\probe-runtime
```

OpenSSL 使用 `--service openssl --pid PID --openssl-probe .\deps\probes\probe-openssl.py`，并指定相同的 Python 和 runtime 参数。探针需要显式启用；解压依赖不会附加到任何进程。应用池身份访问权限应按目标环境配置。适用范围及停止边界见仓库 docs/guide.md。

启动程序会在可执行文件旁创建 sessions（采集数据）和 exports（证据导出存放位置）目录；源码构建放在 bin 时创建在 bin 的上一级。请解压到当前用户可写的文件夹。导出命令仍需通过 --out 指定具体文件名。
