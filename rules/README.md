# 本地规则目录

`traffic-console web` 默认在程序旁的 `rules/` 保存自定义 `.yaml` / `.yml` 文件。从源码构建到 `bin/` 时，默认使用项目根目录下的本目录。也可用 `--rules-dir /path/to/rules` 指定。

在 Web 顶部打开「规则与分析」，新建或导入文件，校验并保存，再选择已停采的会话和规则文件执行分析。内置规则只读，选择文件表示在内置规则基础上追加；自定义规则 ID 必须唯一。

```yaml
- id: CUSTOM-001
  version: 1
  severity: medium
  field: url
  pattern: '(?i)/suspicious-endpoint'
```

单个文件最大 1 MiB，最多 256 个文件。文件名可含字母、数字、点、下划线或短横线，并以字母或数字开头。保存时执行完整校验，并检查文件版本，防止覆盖其他窗口的修改。删除文件不会删除已保存的分析结果；修改规则后需要重新分析。

命令行也可使用此目录中的文件：

```bash
./bin/traffic-console rules check ./rules/custom.yaml
./bin/traffic-console analyze --session ./sessions/case --rules ./rules/custom.yaml
```

本目录下用户保存的 YAML 文件默认被 Git 忽略。
