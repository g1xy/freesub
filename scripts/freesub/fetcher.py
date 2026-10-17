"""节点源抓取：并发拉取、base64 递归展开、跨源归一化去重、源健康度持久化。

源健康度（output/sources_status.json）用于识别长期失效的源：
  - 记录每个源的成功次数、连续失败次数、最近节点产出
  - 连续失败 >= SOURCE_FAIL_THRESHOLD 的源本轮降权到最后抓取，
    但保证至少保留一个可用源，避免全部被跳过导致空订阅
"""
from __future__ import annotations

import base64
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Set, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import config
from .logutil import get_logger

log = get_logger("fetch")

LINK_PATTERN = r"((?:vmess|vless|ss|trojan|hysteria2|hy2)://[^\s\"'<>]+)"
_LINK_RE = re.compile(LINK_PATTERN)
_PROTO_HINT = ("vmess://", "vless://", "ss://", "trojan://", "hy2://", "hysteria2://")


def build_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    })
    retry = Retry(total=2, connect=2, read=2, backoff_factor=0.6,
                  status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset(["GET"]))
    adapter = HTTPAdapter(max_retries=retry, pool_connections=16, pool_maxsize=16)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def extract_nodes_from_text(text: Optional[str]) -> Set[str]:
    """从订阅文本中提取所有节点链接，支持多层 base64 嵌套"""
    results: Set[str] = set()
    if not text:
        return results

    # 只对新解出的增量继续展开：原文一旦混入明文，整体再解码必然失败
    pending = text.strip()
    for _ in range(3):
        try:
            padded = pending + "=" * (-len(pending) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            break
        if len(decoded) > config.MAX_EXPAND_BYTES:
            break
        if not any(p in decoded for p in _PROTO_HINT):
            break
        text += "\n" + decoded
        pending = decoded

    for m in _LINK_RE.findall(text):
        results.add(m.strip().rstrip(".,;\"')"))
    return results


def dedup_nodes(nodes) -> List[str]:
    """按链接核心部分（去掉 # 备注）归一化去重

    同一节点在不同源里备注不同，应视为同一个，否则会重复消耗测活资源。
    """
    seen: Dict[str, str] = {}
    for n in nodes:
        core = n.split("#")[0].strip()
        if core and core not in seen:
            seen[core] = n
    return list(seen.values())


# ---------------------------------------------------------------- 源健康度

class SourceHealth:
    """源健康度追踪，跨轮次持久化到 output/sources_status.json"""

    def __init__(self, path: str = None):
        self.path = path or config.SOURCES_STATUS_FILE
        self.data: Dict[str, Dict[str, object]] = {}
        self._dirty = False
        self.load()

    def load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            sources = raw.get("sources", raw) if isinstance(raw, dict) else {}
            if isinstance(sources, dict):
                self.data = {k: dict(v) for k, v in sources.items() if isinstance(v, dict)}
            log.debug("已载入源健康度记录 %d 条", len(self.data))
        except Exception as exc:  # noqa: BLE001
            log.warning("源健康度文件损坏，忽略: %s", exc)

    def record_success(self, url: str, count: int) -> None:
        entry = self._entry(url)
        entry["consecutive_failures"] = 0
        entry["total_success"] = int(entry.get("total_success", 0)) + 1
        entry["last_success_at"] = _now()
        entry["last_node_count"] = count
        self._dirty = True

    def record_failure(self, url: str, error: str) -> None:
        entry = self._entry(url)
        entry["consecutive_failures"] = int(entry.get("consecutive_failures", 0)) + 1
        entry["total_failure"] = int(entry.get("total_failure", 0)) + 1
        entry["last_failure_at"] = _now()
        entry["last_error"] = error[:200]
        self._dirty = True

    def _entry(self, url: str) -> Dict[str, object]:
        if url not in self.data:
            self.data[url] = {"total_success": 0, "total_failure": 0,
                              "consecutive_failures": 0, "last_node_count": 0}
        return self.data[url]

    def degraded_sources(self, threshold: int) -> List[str]:
        return [u for u, e in self.data.items()
                if int(e.get("consecutive_failures", 0)) >= threshold]

    def order_sources(self, urls: List[str], threshold: int) -> List[str]:
        """把连续失败多的源排到最后，保证健康源优先占用时间预算"""
        healthy = [u for u in urls
                   if int(self.data.get(u, {}).get("consecutive_failures", 0)) < threshold]
        degraded = [u for u in urls
                    if int(self.data.get(u, {}).get("consecutive_failures", 0)) >= threshold]
        if not healthy and urls:
            return urls  # 全部被判降级时仍要抓，不能直接空转
        if degraded:
            log.warning("以下源连续失败 >= %d 次，本轮降权到末尾: %s",
                        threshold, ", ".join(u.rsplit("/", 1)[-1][:28] for u in degraded))
        return healthy + degraded

    def summary(self) -> Dict[str, Dict[str, object]]:
        return {
            url: {
                "total_success": int(e.get("total_success", 0)),
                "total_failure": int(e.get("total_failure", 0)),
                "consecutive_failures": int(e.get("consecutive_failures", 0)),
                "last_node_count": int(e.get("last_node_count", 0)),
                "last_error": e.get("last_error", ""),
                "last_success_at": e.get("last_success_at", ""),
            }
            for url, e in self.data.items()
        }

    def save(self) -> None:
        if not self._dirty:
            return
        config.ensure_directories()
        payload = {"updated_at": _now(), "sources": self.summary()}
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            log.info("源健康度已写入 %s（%d 个源）", self.path, len(payload["sources"]))
        except OSError as exc:
            log.warning("源健康度写入失败: %s", exc)


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------- 抓取入口

def fetch_all_nodes(source_urls: Optional[List[str]] = None,
                    health: Optional[SourceHealth] = None) -> Tuple[List[str], SourceHealth]:
    """并发抓取全部源，返回 (去重后的节点链接列表, 源健康度)"""
    urls = list(source_urls or config.SOURCE_URLS)
    health = health or SourceHealth()
    ordered = health.order_sources(urls, config.SOURCE_FAIL_THRESHOLD)

    log.info("并发抓取 %d 个节点源...", len(ordered))
    session = build_session()

    def fetch_one(url: str) -> Tuple[str, Set[str], Optional[str]]:
        try:
            resp = session.get(url, timeout=config.SOURCE_TIMEOUT_SEC)
            if resp.status_code == 200:
                return url, extract_nodes_from_text(resp.text), None
            return url, set(), f"HTTP {resp.status_code}"
        except Exception as exc:  # noqa: BLE001
            return url, set(), f"{type(exc).__name__}: {exc}"

    nodes: Set[str] = set()
    ok_sources = 0
    workers = min(config.SOURCE_FETCH_WORKERS, len(ordered)) or 1
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for url, extracted, err in executor.map(fetch_one, ordered):
            if err:
                health.record_failure(url, err)
                log.warning("拉取失败 %s -> %s", _short(url), err)
                continue
            health.record_success(url, len(extracted))
            ok_sources += 1
            nodes.update(extracted)
            log.debug("抓取成功 %s -> %d 个节点", _short(url), len(extracted))

    health.save()
    raw_total = len(nodes)
    deduped = dedup_nodes(nodes)
    log.info("源可用 %d/%d | 抓取 %d 个，按核心去重后 %d 个（省去 %d 次重复测活）",
             ok_sources, len(ordered), raw_total, len(deduped), raw_total - len(deduped))
    return deduped, health


def _short(url: str) -> str:
    return url.rsplit("/", 1)[-1][:40] if "/" in url else url[:40]
