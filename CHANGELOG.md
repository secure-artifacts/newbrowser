# 更新记录

## [1.1.8] - 2026-08-14

### 发布定位

**1.1.8 是稳定性与兼容性修复版本。** 本版本将此前针对少数 Windows 终端的 Chrome 识别、活跃 SQLite 数据库读取和异常浏览器残留问题纳入默认的容错路径，并不改变审计规则文件格式或正常用户的操作方式。

### 已修复

| 范畴 | 1.1.8 改进 |
|---|---|
| Windows Chrome 发现 | 优先依据运行账户的 `%LOCALAPPDATA%` 定位资料目录，支持 Chrome Stable、Beta、Dev、Canary、Chrome for Testing、Chromium、Edge、Brave、Arc 及 360 极速 X。 |
| 活跃 Chrome 数据库 | 使用 SQLite Online Backup API 创建一致的只读快照，可读取已提交到 WAL 的记录；不会写入浏览器源数据库。 |
| 异常 Profile 隔离 | 单个 Firefox `places.sqlite`、Chromium `History` 或 Safari 数据库发生权限、安全描述符、锁定、损坏或结构异常时，只跳过该 Profile，继续处理其余配置。 |
| 大规模资料库 | 单个 Profile 设定时间预算，单表设定读取上限，整个任务设定总时间预算；界面明确显示已处理进度。 |
| 手动路径 | 可选择具体 Profile、`User Data`，或其上级 `Google` / `Chrome` 目录。 |
| 诊断隐私 | 复制出的诊断信息仅保留浏览器和 Profile 技术标识；会移除 Local State 中可能含邮箱的 Profile 显示名，并将异常原文压缩为类型/错误代码。 |
| 发布供应链 | 正式构建所用 GitHub Actions 固定为不可变提交，PyInstaller 固定为 `6.10.0`，并在发布前强制运行核心回归测试。 |

### 验证结果

核心自动化回归覆盖 Windows 环境变量发现、多 Chromium 通道、WAL 一致性快照、下载 URL 链、异常数据库隔离、快照限时、读取限额、手动上级目录发现、诊断脱敏、白名单规则和版本一致性。发布流水线同时进行 Windows、Apple Silicon macOS 与 Intel macOS 的原生构建，并生成构建来源证明。

### 已知限制

默认模式仅扫描当前运行账户的标准浏览器资料目录。跨 Windows 用户目录、便携版浏览器和可移动磁盘搜索必须由操作者明确勾选扩展模式并取得相应授权。程序不对 macOS 产物执行 Apple 公证，因此首次启动时仍可能受到系统 Gatekeeper 提示；该提示不影响 Windows 版本。

## [1.1.7]

上一稳定版本。
