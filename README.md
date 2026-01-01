# SSL Monitor Worker

基于 GitHub Action 的 SSL 证书定时监控服务。更多信息请访问 [Guard SSL](https://guardssl.info)。

## 功能特性

- 按订阅等级（Premium > Pro > Free）分优先级执行监控
- 直接连接 PostgreSQL 数据库读写数据
- 多渠道通知：Email、Slack、Discord、Telegram、飞书
- 多语言支持：中文、英文、日文
- 工作流执行汇总通知（发送到管理员飞书）
- 任务执行状态追踪，确保每日任务完成
- 幂等性设计，已完成任务自动跳过
- **断点续作**：中断后可从断点处继续，避免重复检测
- **并行批量处理**：支持并发检测，大幅提升效率
- **通知去重**：确保每个域名每天只发送一次通知
- **证书链安全验证**：完整的证书链提取、验证和安全评分（与 Next.js 保持一致）

## 证书链安全功能

与 Next.js 前端保持一致的证书链安全验证功能：

### 模块说明

| 模块                      | 说明                                                                |
| ------------------------- | ------------------------------------------------------------------- |
| `chain_extractor.py`      | 从 TLS 连接提取完整证书链，包含证书类型、主题、颁发者、有效期等信息 |
| `chain_validator.py`      | 验证证书链完整性，检测过期、即将过期、签名验证等问题                |
| `weak_cipher_detector.py` | 检测弱加密算法（MD5/SHA1签名、弱密钥、不安全协议等）                |
| `security_scorer.py`      | 基于链验证和加密检测结果计算综合安全评分（A+ 到 F）                 |

### 安全评分权重

| 分类       | 权重 | 说明                             |
| ---------- | ---- | -------------------------------- |
| 证书有效性 | 30%  | 检查证书是否过期或即将过期       |
| 链完整性   | 25%  | 检查证书链是否完整、签名是否有效 |
| 加密强度   | 25%  | 检查签名算法、密钥长度、加密套件 |
| 协议版本   | 20%  | 检查 TLS 协议版本是否安全        |

### 数据库字段映射

证书链安全相关数据存储到 `ssl_checks` 表的以下字段：

| 字段名                | 类型    | 说明                                                          |
| --------------------- | ------- | ------------------------------------------------------------- |
| `security_grade`      | text    | 安全评级: A+, A, A-, B, C, D, F                               |
| `security_score`      | integer | 安全评分 (0-100)                                              |
| `has_critical_issues` | boolean | 是否有严重安全问题                                            |
| `security_details`    | text    | 安全评分详情 (JSON: breakdown, recommendations)               |
| `chain_length`        | integer | 证书链长度                                                    |
| `chain_complete`      | boolean | 证书链是否完整                                                |
| `chain_details`       | text    | 证书链详情 (JSON: certificates, earliestExpiry, inferredRoot) |
| `protocol_secure`     | boolean | 协议是否安全                                                  |
| `cipher_secure`       | boolean | 加密套件是否安全                                              |
| `overall_risk`        | text    | 整体风险等级: critical, high, medium, low, none               |
| `cipher_details`      | text    | 加密分析详情 (JSON: issues, protocol, cipher)                 |

### 使用示例

```python
from src.ssl_checker import SSLChecker

checker = SSLChecker()

# 基础检查
result = checker.check("example.com")

# 扩展检查（包含证书链安全验证）
extended_result = checker.check_extended("example.com")

# 访问安全评分
if extended_result.security_score:
    print(f"安全评级: {extended_result.security_score.grade}")
    print(f"数值评分: {extended_result.security_score.numeric_score}/100")

# 访问证书链信息
if extended_result.chain_info:
    print(f"证书链长度: {extended_result.chain_info.chain_length}")
    print(f"链是否完整: {extended_result.chain_info.is_complete}")
```

## 目录结构

```
ssl-monitor-worker/
├── src/
│   ├── __init__.py
│   ├── main.py              # 入口点
│   ├── config.py            # 配置管理
│   ├── db.py                # 数据库操作
│   ├── ssl_checker.py       # SSL 证书检查（含扩展检查）
│   ├── chain_extractor.py   # 证书链提取器
│   ├── chain_validator.py   # 证书链验证器
│   ├── weak_cipher_detector.py  # 弱加密检测器
│   ├── security_scorer.py   # 安全评分器
│   ├── notifier.py          # 多渠道通知发送
│   ├── task_manager.py      # 任务状态管理
│   ├── progress_tracker.py  # 域名级别进度追踪（断点续作）
│   ├── batch_processor.py   # 并行批量处理
│   ├── models.py            # 数据模型
│   └── i18n/                # 多语言支持
│       ├── __init__.py
│       ├── messages.json        # 通知消息模板
│       └── email_templates.json # HTML 邮件模板
├── migrations/              # 数据库迁移脚本
│   └── 001_create_domain_check_progress.sql
├── .github/workflows/       # GitHub Action 工作流
├── requirements.txt
└── README.md
```

## GitHub Action 部署

### 1. 创建独立仓库

将 `ssl-monitor-worker` 目录的内容复制到一个新的 GitHub 仓库。

### 2. 配置 Secrets 和 Variables

在仓库 Settings → Secrets and variables → Actions 中添加：

**Secrets（敏感信息）:**

| Secret 名称          | 说明                        | 必需 |
| -------------------- | --------------------------- | ---- |
| `DATABASE_URL`       | PostgreSQL 数据库连接字符串 | ✅   |
| `FEISHU_WEBHOOK_URL` | 飞书机器人 Webhook URL      | ✅   |
| `BREVO_API_KEY`      | Brevo 邮件 API Key          | ✅   |
| `BREVO_SENDER_EMAIL` | 发件人邮箱                  | ❌   |
| `BREVO_SENDER_NAME`  | 发件人名称                  | ❌   |

**Variables（品牌配置）:**

| Variable 名称      | 说明             | 默认值                          |
| ------------------ | ---------------- | ------------------------------- |
| `BRAND_NAME`       | 品牌名称         | Guard SSL                       |
| `BRAND_URL`        | 网站首页链接     | https://guardssl.info           |
| `DASHBOARD_URL`    | 控制台链接       | https://guardssl.info/dashboard |
| `BATCH_SIZE`       | 每批并发检测数量 | 10                              |
| `RATE_LIMIT_DELAY` | 请求间隔（秒）   | 0.1                             |
| `MAX_WORKERS`      | 最大工作线程数   | 10                              |

### 3. 获取飞书 Webhook URL

1. 打开飞书群组
2. 点击群组设置 → "群机器人"
3. 添加"自定义机器人"
4. 设置机器人名称（如 "SSL 监控"）
5. 复制 Webhook URL

### 4. 执行时间

工作流会按以下时间自动执行：

| 订阅等级 | UTC 时间 | 北京时间 |
| -------- | -------- | -------- |
| Premium  | 00:00    | 08:00    |
| Pro      | 01:00    | 09:00    |
| Free     | 02:00    | 10:00    |

### 5. 手动触发

可以在 GitHub Actions 页面手动触发工作流，支持：

- 指定任务日期
- 试运行模式（不发送通知）

## 通知机制

### 1. 用户通知

根据用户在系统中配置的通知渠道和语言偏好发送：

- **Email**: 支持 HTML 富文本邮件
- **Slack**: Webhook 消息
- **Discord**: Embed 消息
- **Telegram**: Bot 消息
- **飞书**: 卡片消息
- **站内消息**: 系统消息通知

### 2. 管理员通知

每次工作流执行完成后，会向管理员飞书发送汇总报告：

```
✅ SSL 监控任务完成 - PREMIUM

📅 任务日期: 2024-01-15
🏷️ 订阅等级: PREMIUM
📊 域名总数: 50
🔄 本次检测: 48
⏭️ 跳过(已检测): 2
✅ 检查成功: 48
❌ 检查失败: 2
⚠️ 即将过期: 3
🚨 已过期: 1
💥 检查错误: 2
⏱️ 执行耗时: 45.2 秒
```

## 断点续作机制

当任务中途中断（如 GitHub Action 超时、网络问题等）时，系统会：

1. **记录进度**：每个域名检测完成后立即保存状态到 `domain_check_progress` 表
2. **恢复执行**：重新运行时自动跳过已完成的域名
3. **通知去重**：已发送通知的域名不会重复发送

### 数据库迁移

首次使用前需要执行迁移脚本创建进度表：

```bash
psql $DATABASE_URL -f migrations/001_create_domain_check_progress.sql
```

## 多语言支持

通知消息支持以下语言：

- `zh-CN` - 简体中文（默认）
- `en` - English
- `ja` - 日本語

语言偏好从用户的 `notification_settings` 表中读取。

### 消息模板位置

- 普通消息: `src/i18n/messages.json`
- HTML 邮件: `src/i18n/email_templates.json`

## 本地开发

```bash
# 安装依赖
pip install -r requirements.txt

# 复制环境变量模板
cp .env.example .env

# 编辑 .env 填入实际配置

# 执行数据库迁移（首次使用）
psql $DATABASE_URL -f migrations/001_create_domain_check_progress.sql

# 运行监控（指定订阅等级）
python -m src.main --tier premium
python -m src.main --tier pro
python -m src.main --tier free

# 试运行模式
python -m src.main --tier premium --dry-run

# 指定批处理大小
python -m src.main --tier premium --batch-size 20

# 指定任务日期
python -m src.main --tier premium --date 2024-01-15
```

## 通知消息示例

### 证书即将过期

> ⚠️ 域名 example.com 的 SSL 证书将在 15 天后过期，请及时更新。

### 证书已过期

> ⚠️ 域名 example.com 的 SSL 证书已过期！请立即更新。

### 检查失败

> ❌ 域名 example.com 的 SSL 证书检查失败：连接超时
