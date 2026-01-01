import argparse
import gzip
import json
import os
import sys
import xml.etree.ElementTree as ET
from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, Iterable, List, Optional, Set, Tuple

import requests
from google.oauth2 import service_account
from googleapiclient.discovery import build


_WEBMASTERS_READONLY_SCOPE = "https://www.googleapis.com/auth/webmasters.readonly"
_WEBMASTERS_SCOPE = "https://www.googleapis.com/auth/webmasters"  # 提交 sitemap 需要写权限


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _build_gsc_service(service_account_file: str, readonly: bool = True):
    """构建 GSC 服务，readonly=False 时使用写权限（用于提交 sitemap）"""
    scope = _WEBMASTERS_READONLY_SCOPE if readonly else _WEBMASTERS_SCOPE
    creds = service_account.Credentials.from_service_account_file(
        service_account_file,
        scopes=[scope],
    )
    return build("searchconsole", "v1", credentials=creds, cache_discovery=False)


def _list_sitemaps(service, site_url: str) -> List[Dict]:
    resp = service.sitemaps().list(siteUrl=site_url).execute()
    items = resp.get("sitemap")
    if not items:
        return []
    if isinstance(items, list):
        return items
    return [items]


def _submit_sitemap(service, site_url: str, sitemap_url: str) -> Dict:
    """提交 sitemap 到 Google Search Console"""
    try:
        service.sitemaps().submit(siteUrl=site_url, feedpath=sitemap_url).execute()
        return {"sitemap_url": sitemap_url, "status": "submitted", "error": None}
    except Exception as e:
        return {"sitemap_url": sitemap_url, "status": "failed", "error": str(e)}


def _maybe_decompress(content: bytes, url: str, content_encoding: str) -> bytes:
    if url.endswith(".gz") or "gzip" in (content_encoding or "").lower():
        return gzip.decompress(content)
    return content


def _fetch_bytes(session: requests.Session, url: str, timeout_sec: int) -> bytes:
    resp = session.get(
        url,
        timeout=timeout_sec,
        headers={
            "User-Agent": "ssl-monitor-worker/1.0 (sitemap fetcher)",
            "Accept": "application/xml,text/xml,*/*",
        },
    )
    resp.raise_for_status()
    return _maybe_decompress(resp.content, url, resp.headers.get("Content-Encoding", ""))


def _parse_sitemap(xml_bytes: bytes) -> Tuple[List[str], List[str]]:
    root = ET.fromstring(xml_bytes)
    tag = root.tag.split("}")[-1]

    if tag == "sitemapindex":
        locs = root.findall(".//{*}sitemap/{*}loc")
        return ([loc.text.strip() for loc in locs if loc.text], [])

    if tag == "urlset":
        locs = root.findall(".//{*}url/{*}loc")
        return ([], [loc.text.strip() for loc in locs if loc.text])

    return ([], [])


def _crawl_sitemaps(
    session: requests.Session,
    start_sitemap_urls: Iterable[str],
    *,
    max_depth: int,
    max_sitemaps: int,
    max_urls: int,
    timeout_sec: int,
) -> Tuple[List[str], List[str], List[Dict]]:
    visited: Set[str] = set()
    discovered_urls: List[str] = []
    fetched_sitemaps: List[str] = []
    errors: List[Dict] = []

    q: Deque[Tuple[str, int]] = deque((u, 0) for u in start_sitemap_urls)

    def _urls_limit_reached() -> bool:
        return max_urls > 0 and len(discovered_urls) >= max_urls

    while q:
        sitemap_url, depth = q.popleft()
        if sitemap_url in visited:
            continue
        if len(visited) >= max_sitemaps:
            break
        if depth > max_depth:
            continue

        visited.add(sitemap_url)

        try:
            xml_bytes = _fetch_bytes(session, sitemap_url, timeout_sec=timeout_sec)
            child_sitemaps, urls = _parse_sitemap(xml_bytes)

            fetched_sitemaps.append(sitemap_url)

            for u in urls:
                if _urls_limit_reached():
                    break
                discovered_urls.append(u)

            if depth < max_depth and not _urls_limit_reached():
                for child in child_sitemaps:
                    if child and child not in visited:
                        q.append((child, depth + 1))

        except Exception as e:  # noqa: BLE001
            errors.append({"sitemap_url": sitemap_url, "error": str(e)})

    return fetched_sitemaps, discovered_urls, errors


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--site-url", required=True)
    parser.add_argument("--service-account-file", required=True)
    parser.add_argument("--out-dir", default="out")
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--max-sitemaps", type=int, default=200)
    parser.add_argument("--max-urls", type=int, default=200000)
    parser.add_argument("--timeout-sec", type=int, default=30)
    parser.add_argument("--submit", nargs="*", metavar="SITEMAP_URL",
                        help="提交 sitemap URL 到 GSC，可指定多个。不带参数则自动提交网站的 sitemap.xml")
    parser.add_argument("--verbose", "-v", action="store_true", help="显示详细信息")

    args = parser.parse_args(argv)

    _ensure_dir(args.out_dir)

    # 如果是提交模式
    if args.submit is not None:
        service = _build_gsc_service(args.service_account_file, readonly=False)
        
        # 如果没有指定 sitemap URL，自动使用网站的 sitemap.xml
        sitemap_urls_to_submit = args.submit if args.submit else []
        if not sitemap_urls_to_submit:
            # 从 site_url 推断默认 sitemap 地址
            base_url = args.site_url.replace("sc-domain:", "https://")
            if not base_url.startswith("http"):
                base_url = f"https://{base_url}"
            base_url = base_url.rstrip("/")
            sitemap_urls_to_submit = [f"{base_url}/sitemap.xml"]
        
        results = []
        for sitemap_url in sitemap_urls_to_submit:
            if args.verbose:
                print(f"正在提交: {sitemap_url}")
            result = _submit_sitemap(service, args.site_url, sitemap_url)
            results.append(result)
            if result["status"] == "submitted":
                print(f"✓ 提交成功: {sitemap_url}")
            else:
                print(f"✗ 提交失败: {sitemap_url} - {result['error']}", file=sys.stderr)
        
        # 保存提交结果
        submit_summary = {
            "site_url": args.site_url,
            "submitted_at": _utc_now_iso(),
            "results": results,
        }
        with open(os.path.join(args.out_dir, "submit_result.json"), "w", encoding="utf-8") as f:
            json.dump(submit_summary, f, ensure_ascii=False, indent=2)
        
        failed = [r for r in results if r["status"] == "failed"]
        if failed:
            return 2
        return 0

    # 原有的读取模式
    service = _build_gsc_service(args.service_account_file, readonly=True)
    gsc_sitemaps = _list_sitemaps(service, args.site_url)
    sitemap_urls = [item.get("path") for item in gsc_sitemaps if item.get("path")]

    if args.verbose:
        print(f"从 GSC 获取到 {len(sitemap_urls)} 个 sitemap:")
        for url in sitemap_urls:
            print(f"  - {url}")

    session = requests.Session()
    fetched_sitemaps, urls, errors = _crawl_sitemaps(
        session,
        sitemap_urls,
        max_depth=args.max_depth,
        max_sitemaps=args.max_sitemaps,
        max_urls=args.max_urls,
        timeout_sec=args.timeout_sec,
    )

    with open(os.path.join(args.out_dir, "gsc_sitemaps.json"), "w", encoding="utf-8") as f:
        json.dump(gsc_sitemaps, f, ensure_ascii=False, indent=2)

    with open(os.path.join(args.out_dir, "urls.txt"), "w", encoding="utf-8") as f:
        for u in urls:
            f.write(u)
            f.write("\n")

    summary = {
        "site_url": args.site_url,
        "generated_at": _utc_now_iso(),
        "gsc_sitemap_count": len(sitemap_urls),
        "fetched_sitemap_count": len(fetched_sitemaps),
        "url_count": len(urls),
        "errors": errors,
        "fetched_sitemaps": fetched_sitemaps,
        "limits": {
            "max_depth": args.max_depth,
            "max_sitemaps": args.max_sitemaps,
            "max_urls": args.max_urls,
        },
    }

    with open(os.path.join(args.out_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    if errors:
        print(f"Completed with {len(errors)} errors", file=sys.stderr)
        return 2

    print(f"Done. sitemaps={len(fetched_sitemaps)} urls={len(urls)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
