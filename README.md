# vault-manager（工程账本）

一站式管理个人网页工程的「超管/普通链接、账号密码、简介」，以及日常密码、二维码等。
**零知识加密**：所有明文与保险库密钥只在浏览器端（Web Crypto，PBKDF2 + AES-GCM）处理，服务端（腾讯云 SCF）只存密文，永不接触明文。

## 架构

- **后端**：腾讯云 SCF Web 函数 `vlt-mgr`（Python 3.10 + Flask 3.x），纯 JSON API，**不托管任何 HTML/静态文件**（避免被 API 网关当附件下载）。
- **存储**：腾讯云 COS 桶 `vlt-mgr-1256784020`（密文 + 元数据）。
- **前端**：本仓库 `index.html` + `static/`，经 **GitHub Pages** 发布（多端访问入口）。

## 三个访问地址

1. SCF 直连（API）：`https://1256784020-5x5qs04wi9.ap-guangzhou.tencentscf.com`
2. GitHub Pages（前端）：`https://amillionpound.github.io/vault-manager/`
3. CloudStudio 沙箱（前端预览，可选）

前端默认已内置 SCF API 地址；如需修改，点页面底部 ⚙ 设置。

## 部署（CI/CD）

`push main` → GitHub Actions 自动：
- `deploy-scf`：装 Flask 进 vendor → 打包 → 更新 SCF 函数代码 → 健康检查。需要 Secrets `TENCENT_SECRET_ID` / `TENCENT_SECRET_KEY`。
- `deploy-pages`：发布 `index.html` + `static/` 到 GitHub Pages。需在仓库 Settings → Pages 把 Source 设为 **GitHub Actions**。

## SCF 环境变量（首次使用需在 SCF 控制台设置）

- `ADMIN_PWD`：管理员密码的 SHA-256 hex（用页面内「自算密钥」工具生成）。
- `SESSION_SECRET`：会话签名密钥（任意长随机串）。
- `COS_BUCKET` / `COS_REGION` / `COS_SECRET_ID` / `COS_SECRET_KEY`：COS 凭据（子用户 `vlt-cos-writer` + 策略 `vlt-cos-access`）。
- `ADMIN_TOTP_SECRET`（可选）：TOTP 动态码。

> 安全模型（v3.1 信封加密、绝密区、应急恢复等）为后续需求，当前仓库为可运行空壳骨架。
