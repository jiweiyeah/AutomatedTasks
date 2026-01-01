# Google Sitemap Fetcher

用于在本地或 GitHub Actions 中，借助 Google Search Console (GSC) API：

- **抓取** sitemap 数据并解析出 URL 列表
- **提交** sitemap 到 Google Search Console

## 一、运行前提

1. 在 Google Cloud Console 中创建项目并启用 **Google Search Console API**。
2. 创建 Service Account，下载 JSON Key 文件，并在 Search Console 的对应 property（`siteUrl`）中授予该账号「完整权限」。
3. 确保本机已安装 Python 3.11+，并执行依赖安装：
   ```bash
   pip install -r google_sitemap_fetcher/requirements.txt
   ```

## 二、所需变量及获取方式

| 名称                              | 说明                                                              | 获取方式                                   |
| --------------------------------- | ----------------------------------------------------------------- | ------------------------------------------ |
| `GSC_SITE_URL`                    | Search Console property 的 `siteUrl`（如 `https://example.com/`） | Search Console → 设置 → Property 设置      |
| `GSC_SERVICE_ACCOUNT_JSON`        | Service Account JSON Key 的绝对路径（本地运行）                   | 下载 JSON Key 文件，放在安全位置           |
| `GSC_SERVICE_ACCOUNT_JSON_BASE64` | Service Account JSON Key 的 Base64 字符串（GitHub Action）        | `base64 -i gsc-service-account.json` 输出的值 |
| `MAX_URLS`                        | 限制解析的 URL 数量（0 表示不限制）                               | 按需自定义，默认 200000                    |

> GitHub Actions 中还需要在仓库 `Variables` 里设置 `GSC_SITE_URL`；`.workflow_dispatch` 触发时也可以直接输入。

## 三、本地运行示例

### 3.1 抓取 sitemap（读取模式）

1. 在仓库根目录创建 `.env`（可复用现有 `.env` 文件）：
   ```env
   GSC_SITE_URL=https://example.com/
   GSC_SERVICE_ACCOUNT_JSON=/absolute/path/to/gsc-service-account.json
   MAX_URLS=200000
   ```
2. 在终端加载 `.env` 并执行：

   ```bash
   set -a
   source .env
   set +a

   python -m google_sitemap_fetcher.main \
     --site-url "$GSC_SITE_URL" \
     --service-account-file "$GSC_SERVICE_ACCOUNT_JSON" \
     --out-dir out \
     --max-urls "${MAX_URLS:-200000}"
   ```

3. 输出结果位于 `out/` 目录：
   - `gsc_sitemaps.json`：GSC 返回的 sitemap 列表
   - `urls.txt`：解析得到的 URL（每行一个）
   - `summary.json`：包含统计与错误信息

### 3.2 提交 sitemap（写入模式）

#### 提交默认的 sitemap.xml

```bash
python -m google_sitemap_fetcher.main \
  --site-url "$GSC_SITE_URL" \
  --service-account-file "$GSC_SERVICE_ACCOUNT_JSON" \
  --submit
```

#### 提交指定的 sitemap URL

```bash
python -m google_sitemap_fetcher.main \
  --site-url "$GSC_SITE_URL" \
  --service-account-file "$GSC_SERVICE_ACCOUNT_JSON" \
  --submit "https://example.com/sitemap.xml" "https://example.com/sitemap-blog.xml"
```

#### 显示详细信息

```bash
python -m google_sitemap_fetcher.main \
  --site-url "$GSC_SITE_URL" \
  --service-account-file "$GSC_SERVICE_ACCOUNT_JSON" \
  --submit -v
```

提交结果会保存到 `out/submit_result.json`，也可在 Google Search Console 的「站点地图」页面查看提交状态。

## 四、GitHub Actions 运行

- Workflow 文件：`.github/workflows/google-sitemap-fetch.yml`
- Secrets：
  - `GSC_SERVICE_ACCOUNT_JSON_BASE64`
- Variables：
  - `GSC_SITE_URL`

手动触发时可以覆盖 `site_url`、`max_urls`。工作流会把 `out/` 目录作为 artifact 上传，即使失败也能便于调试。

## 五、常见问题

1. **`SITE_URL is empty`**：确认 `.env`、运行参数或 GitHub Repository Variable 中已设置 `GSC_SITE_URL`。
2. **`403 Insufficient Permission`**：确保 Service Account 被添加进 Search Console，对应 property 已授予权限。
3. **`base64: invalid input`**：在 macOS/Linux 上使用 `base64 gsc-service-account.json | pbcopy` 获得纯文本，再写入 Secrets。
