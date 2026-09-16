# API Scan Tool

这是一个只监听本机的 API 安全检查工具：先用 Semgrep 扫描 Java、Python、JavaScript 源码，再用 OpenAI 或 DeepSeek 复查命中；最后可选地经 Burp Suite 发送少量、受控的验证请求并生成报告。

默认只运行“源码扫描 + AI 复查”。**Burp 是可选的**，没有安装或没有启动 Burp 也能正常扫描；未启用 Burp 时工具不会向任何目标 URL 发送请求。

仅用于你拥有或已经获得明确授权的代码和目标。

## 最简单的使用方法：EXE

1. 打开 `release\API-Scan-Tool` 文件夹。不要只复制其中的 `API-Scan-Tool.exe`，同目录的 `_internal` 和 `semgrep` 文件夹也必须保留。
2. 将 `.env.example` 复制一份并重命名为 `.env`。
3. 用记事本打开 `.env`。根据网页中选择的 AI 提供商，填写对应的一行 API Key：

   ```text
   OPENAI_API_KEY=你的_OpenAI_API_Key
   DEEPSEEK_API_KEY=你的_DeepSeek_API_Key
   ```

   OpenAI Key 在 [OpenAI API Keys 页面](https://platform.openai.com/api-keys) 创建和管理；DeepSeek Key 在 [DeepSeek 平台](https://platform.deepseek.com/api_keys) 创建和管理。只需要填写你实际选择的提供商对应的 Key。不要把 `.env` 发给别人，也不要把它提交到 Git。
4. 双击 `API-Scan-Tool.exe`。浏览器会打开 `http://127.0.0.1:8765`。
5. 填写“源码目录”，选择语言和模型，然后点击“启动扫描”。第一次使用可保持 Burp 不勾选。

网页顶部会显示当前选中提供商的 Key 是否已配置。若显示缺少 Key，请确认 `.env` 与 EXE 在同一个文件夹，文件名不是 `.env.txt`，并重启程序。

## 网页表单逐项说明

| 项目 | 何时填写 | 示例 |
| --- | --- | --- |
| 源码目录 | 每次必填 | `D:\project\my-service` |
| 目标 URL | 仅启用 Burp 验证时必填 | `http://127.0.0.1:9101` |
| AI 提供商与模型 | 直接点击卡片选择 | OpenAI（Terra/Luna/Sol）或 DeepSeek（Flash/Pro） |
| 允许列表 | 仅启用 Burp 时必填 | `127.0.0.1:9101` 或 `api.example.com:443` |
| 认证头 | 目标 API 需要登录时才填写 | `Authorization: Bearer <token>` |
| Burp 主机 / 端口 | 仅启用 Burp 时填写 | 通常保留 `127.0.0.1` / `8080` |
| Burp CA PEM | 仅 HTTPS 且 Burp 解密 HTTPS 时填写 | `C:\certs\burp-ca.pem` |

### 什么是认证头？

很多 API 会先检查登录凭据，例如 `Authorization: Bearer <token>` 或 `X-API-Key: <key>`。把已有的测试账号令牌写在“认证头”中，工具在 **Burp 已启用时** 才会把它随受控验证请求发送给目标；本地演示不需要填写。认证头的值不会写进历史任务、报告或网页返回的数据。

请使用权限最小、可撤销的测试凭据，绝不使用生产管理员令牌。

## Burp Suite：需要时再启用

如果只希望检查源码，保持“启用 Burp Suite 抓包和受控验证”未勾选即可。

若确实需要验证：

1. 先启动 Burp Suite，进入 `Proxy`，确认 listener 为 `127.0.0.1:8080`（或把实际地址填入表单）。
2. 在 `Proxy` 中关闭 `Intercept is on`，否则 Burp 会等待人工点击，自动任务会超时。
3. 勾选网页中的 Burp 选项，填入目标 URL 与同一目标的 `host:port` 允许列表。例如 URL 为 `http://127.0.0.1:9101`，允许列表就填 `127.0.0.1:9101`。
4. 若目标是 HTTPS，导出 Burp CA 的 PEM 文件并在表单填入路径；否则证书校验会安全失败。
5. 勾选已获授权确认框，再启动扫描。

开启 Burp 后，工具仅对允许列表内的地址发送数量受限的无副作用探测；外部目标不会执行写入、删除、爆破、拒绝服务、内网/元数据探测或命令执行。重定向到允许列表外也会被拒绝。

## 内置本地演示：确实有目标 URL

仓库内包含三个故意存在漏洞的**本地**服务。它们只有在启动演示后才是可访问的目标 URL，绝不能部署到任何环境。

开发环境中打开 PowerShell，执行：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m api_scan_tool demo
```

该命令会启动可用的示例服务（Python、Node.js、JDK 未安装的语言会显示跳过）。对应源码目录、URL 和允许列表如下：

| 语言 | 源码目录 | 目标 URL | 允许列表 |
| --- | --- | --- | --- |
| Python | `examples\python_vulnerable` | `http://127.0.0.1:9101/fetch?url=http://127.0.0.1:9199/marker` | `127.0.0.1:9101` |
| JavaScript | `examples\javascript_vulnerable` | `http://127.0.0.1:9102/file?name=../fixture-secret.txt` | `127.0.0.1:9102` |
| Java | `examples\java_vulnerable` | `http://127.0.0.1:9103/run?cmd=echo%20api_scan_marker_9f3a` | `127.0.0.1:9103` |

然后运行 Web 控制台，在表单中选择其中一行。若要看到 Burp 抓包，按上节启动 Burp、勾选 Burp 和授权确认；若没有 Burp，也可以不填目标 URL，直接完成该目录的 Semgrep 与 AI 复查。

EXE 会打包扫描器和网页控制台；三个跨语言演示服务依赖外部 Python/Node.js/JDK，因此请用上面的开发环境命令启动它们。

## 从源码运行（开发者）

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
python -m api_scan_tool web
```

命令行也可使用：

```powershell
python -m api_scan_tool run --source .\examples\python_vulnerable
python -m api_scan_tool run --source .\examples\python_vulnerable --target http://127.0.0.1:9101 --allow 127.0.0.1:9101 --use-burp --confirm-authorized
```

网页使用固定的提供商与模型选择，不要求设置 `OPENAI_MODEL`。CLI 使用 DeepSeek 的示例：`python -m api_scan_tool run --source .\examples\python_vulnerable --ai-provider deepseek --model deepseek-flash`。

## 报告与隐私

每个任务会在 `runs` 目录生成 JSON、HTML 和 SARIF 报告，网页也可下载。发送给选中 AI 提供商的内容仅包括脱敏后的 Semgrep 命中片段和有限上下文。OpenAI 请求设置为 `store=false`；使用 DeepSeek 前请按其自身的数据政策评估。有关模型见 [OpenAI 模型目录](https://developers.openai.com/api/docs/models) 和 [DeepSeek API 文档](https://api-docs.deepseek.com/quick_start/pricing-details-cny/)。

## 重新构建 EXE

在开发环境执行：

```powershell
.\build_exe.ps1
```

完成后将整个 `release\API-Scan-Tool` 文件夹交付给使用者；构建脚本会把 `.env.example` 一并放入该目录。

默认构建会复用未变化的 Semgrep 运行器和 PyInstaller 缓存，因此后续只改网页或 Python 代码时会快很多。首次构建、升级 Semgrep 或需要完全干净的包时使用：

```powershell
.\build_exe.ps1 -Clean
```

只想强制重建 Semgrep 运行器时使用：

```powershell
.\build_exe.ps1 -RebuildSemgrep
```

若提示 `API-Scan-Tool.exe is still running`，浏览器页面关闭并不代表程序退出。可在任务管理器结束 `API-Scan-Tool.exe`，或直接使用：

```powershell
.\build_exe.ps1 -StopRunning
```

构建脚本默认不会重复下载或检查全部依赖，首次安装依赖、更新依赖后或提示缺少依赖时才使用：

```powershell
.\build_exe.ps1 -InstallDependencies
```
