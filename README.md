# 浏览器痕迹分析 (newbrowser)

## 如何发布新版本

本项目使用 GitHub Actions 自动构建和发布。每次发布新版本只需要创建一个 Git Tag 并推送即可。

### 发布步骤

#### 1. 确保代码已提交并推送

在发布之前，确保你的所有代码改动已经提交并推送到 GitHub：

```bash
# 查看当前状态
git status

# 添加所有改动
git add .

# 提交改动（把"你的改动说明"替换成实际的描述）
git commit -m "你的改动说明"

# 推送到 GitHub
git push origin main
```

#### 2. 创建版本 Tag

Git Tag 是一个版本标记，用于标识发布的版本号。版本号格式为 `v主版本.次版本.修订版本`，例如 `v1.0.0`、`v1.1.0`、`v2.0.0`。

```bash
# 创建一个新的版本 tag（将 v1.0.1 替换为你想要的版本号）
git tag -a v1.0.1 -m "Release version 1.0.1"
```

#### 3. 推送 Tag 触发自动构建

```bash
# 推送 tag 到 GitHub（这会自动触发 CI 构建）
git push origin v1.0.1
```

推送后，GitHub Actions 会自动执行以下操作：

1. 在 Windows / macOS 多平台上构建可执行文件
2. 生成安全签名（Attestation）
3. 创建 Release 并上传构建产物

#### 4. 查看构建结果

- 构建进度：访问项目的 **Actions** 页面查看
- 发布结果：访问项目的 **Releases** 页面查看已发布的文件

### 版本号说明

| 版本号格式 | 什么时候用 | 示例 |
|-----------|-----------|------|
| `vX.0.0` | 重大更新、不兼容改动 | `v2.0.0` |
| `vX.Y.0` | 新增功能 | `v1.1.0` |
| `vX.Y.Z` | 修复 bug | `v1.0.1` |

### 如果构建失败怎么办

1. 访问项目的 **Actions** 页面查看错误日志
2. 修复代码问题
3. 删除失败的 tag 并重新创建：

```bash
# 删除本地 tag
git tag -d v1.0.1

# 删除远程 tag
git push origin :refs/tags/v1.0.1

# 修复问题后，重新创建并推送
git tag -a v1.0.1 -m "Release version 1.0.1"
git push origin v1.0.1
```

### 重要提醒

- **禁止**在 GitHub 网页上手动创建 Release 或手动上传 zip 文件
- 所有产物必须由 `github-actions[bot]` 自动上传，否则安全平台审核会失败
- 版本 tag 必须以 `v` 开头（如 `v1.0.1`）
