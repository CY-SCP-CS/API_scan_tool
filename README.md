# Code Check · AI 源码审查

当前 `ai-source-review` 分支是一个只监听 `127.0.0.1` 的纯 AI 源码审查工具。它专门审查“未登录即可访问受限接口”问题，并输出最终 Markdown 报告。

完整的“源码扫描 + OpenAPI 黑盒 + Burp”工具保留在 `full-api-scan` 分支。

## 最简单的使用方式

1. 在 EXE 文件夹内将 `.env.example` 复制为 `.env`。首次启动 EXE 时也会自动创建这个仅含占位符的 `.env` 文件。
2. 填写一个提供商的密钥：

   ```text
   OPENAI_API_KEY=你的_OpenAI_Key
   # 或
   DEEPSEEK_API_KEY=你的_DeepSeek_Key
   ```

3. 双击 `Code-Check.exe`，浏览器会打开 `http://127.0.0.1:8787`。
4. 填写待审查源码的绝对路径，选择提供商和模型，点击“开始 AI 审查”。
5. 审查完成后下载最终 `.md` 报告。

密钥不会被写入报告、日志或 Git；不要把 `.env` 发送给他人。EXE 不硬编码真实 API Key，因为任何取得 EXE 的人都能提取其中的密钥。

## 审查范围与隐私

- 只读取本机代码与配置；不访问业务目标、不使用 Burp、不发起动态攻击。
- 自动排除 `.git`、`node_modules`、`target`、`dist`、虚拟环境等目录。
- 优先读取路由、认证、过滤器、拦截器、控制器和配置文件；大项目按上限抽取上下文。
- 发送给 AI 前会脱敏常见 API Key、Token、密码和数据库连接串。
- 报告要求模型只给出有证据的确认问题和待核实问题，并在信息不足时说明覆盖缺口。

## 从源码启动

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python codecheck_launcher.py
```

## 构建与交付 EXE

```powershell
powershell -ExecutionPolicy Bypass -File .\build_codecheck_exe.ps1
```

交付整个 `release\Code-Check` 文件夹，不能只复制 `Code-Check.exe`；`_internal` 和 `.env.example` 都必须保留。

在另一台 Windows 电脑上使用前，先运行本机自检：

```powershell
powershell -ExecutionPolicy Bypass -File .\test_codecheck_portable.ps1
```

自检会启动 EXE、请求本机健康检查接口、再停止它。目标电脑需要 64 位 Windows；不需要安装 Python、Node.js、Semgrep 或 Burp。联网仅在用户实际提交审查任务、调用选择的 AI 提供商时需要。
