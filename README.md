# 浏览器痕迹分析

浏览器痕迹分析是一个本地运行的 Windows/macOS 浏览器资料审计工具。它在获得操作者授权的前提下读取浏览历史、下载记录和书签，并依照本地规则库生成审计报告。程序不会上传浏览器数据库或网址数据。

当前稳定发布目标为 **v1.1.8**。本版本重点提升 Windows Chrome 资料发现、活跃 SQLite/WAL 一致性读取、异常 Profile 隔离、诊断隐私和发布供应链稳定性。完整变更见 [CHANGELOG.md](CHANGELOG.md)。

## 使用边界

默认模式只检查当前运行账户的标准浏览器资料目录。扩展兼容搜索会检查同机其他用户目录、固定盘和可移动盘中的浅层便携版痕迹，必须在具有明确授权时使用。软件设计为只读访问浏览器源资料；扫描期间会创建临时 SQLite 快照，任务结束或程序退出时清理。

> 诊断文本可用于支持排障，但不应包含浏览器数据库、Cookie、登录数据、书签、真实网址或账号截图。v1.1.8 的复制诊断已移除 Profile 显示名中的账号信息，并将底层异常压缩为类型/错误代码。

## 发布流程

正式发布由 GitHub Actions 完成。只有严格符合 `vMAJOR.MINOR.PATCH` 格式的 Git tag 才允许进入构建流程；构建前会运行核心回归测试，再生成 Windows、Apple Silicon macOS 和 Intel macOS 的 ZIP 包、构建来源证明与 GitHub Release。

```bash
# 1. 在 release/v1.1.8 分支完成审查、测试并合并到 main
# 2. 仅在 main 对应提交上创建带注释的发布标签
git tag -a v1.1.8 -m "Release v1.1.8"
git push origin v1.1.8
```

发布完成后，应在 GitHub Release 中核对各资产的名称、平台、下载大小、构建来源证明和 SHA-256。发布失败时不要复用同一标签覆盖已发布资产；应先调查失败原因，再创建新的修复版本标签，例如 `v1.1.9`。

## 本地验证

开发或发布前，请运行：

```bash
BROWSER_AUDIT_HEADLESS_TESTS=1 python3 -m py_compile browser_Gui.py tests/test_browser_core.py
BROWSER_AUDIT_HEADLESS_TESTS=1 python3 -m unittest discover -s tests -v
```

Windows 测试包可通过分支专用的 `Build Windows Test Package` 工作流构建；正式版本必须依赖 `Build and Release with Attestation` 工作流发布，禁止手工上传可执行包替代自动化产物。

## 回滚

如发现 1.1.8 重大问题，应停止分发对应资产、记录受影响范围，并在 `main` 基于已验证的提交发布递增修复版本。不要删除用户已下载的文件，也不要强制删除历史 Release 或覆盖既有 tag，以保留审计追溯能力。
