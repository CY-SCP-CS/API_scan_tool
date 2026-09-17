# Code Check · AI 源码审查

这是 `ai-source-review` 分支中的本机网页界面。它只审查本机源码目录，不包含目标 URL、OpenAPI、Burp 或动态验证功能。

## 使用

1. 复制仓库根目录的 `.env.example` 为 `.env`，在其中填写 `OPENAI_API_KEY` 或 `DEEPSEEK_API_KEY`。
2. 启动：`python codecheck_launcher.py`。
3. 浏览器打开 `http://127.0.0.1:8787`，填写源码绝对路径，选择提供商和模型。
4. 完成后下载最终 Markdown 报告。

后端会排除常见构建与依赖目录，并优先读取路由、认证、过滤器、拦截器、配置等文件。发送给模型前会脱敏常见 API Key、Token、密码和数据库连接串。大项目采用有上限的按需读取策略，因此报告会如实说明覆盖缺口。

## EXE

运行仓库根目录的 `build_codecheck_exe.ps1` 后，交付整个 `release\Code-Check` 文件夹。不要只复制 EXE；同目录的 `_internal` 必须保留。

API Key 不会编译进 EXE。真实密钥应只保存在接收方电脑上、与 EXE 同目录的 `.env` 文件或系统环境变量中；`.env` 已被 `.gitignore` 排除。
