"""产物导出与报告生成：订阅文件、README 动态表格、meta.json。"""
from __future__ import annotations

import base64
import json
import os
import shutil
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

import yaml

from . import config
from .exporters import export_clash_yaml, export_singbox_json, format_node_group
from .logutil import get_logger, report_drop_stats, snapshot_drops

log = get_logger("report")


def _write_b64(path: str, links: List[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(links).encode()).decode())


def _count_file(path: str) -> int:
    if not os.path.exists(path):
        return 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
        if not content:
            return 0
        decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
        return len([line for line in decoded.splitlines() if line.strip()])
    except Exception:  # noqa: BLE001
        return 0


def count_published_nodes() -> int:
    """读取上一版已发布的全量节点数，用于空结果保护"""
    return _count_file(os.path.join(config.OUTPUT_DIR, "v2ray.txt"))


def export_subscriptions(verified_nodes: List[Dict[str, Any]]) -> Tuple[int, int]:
    """导出全量 / 家宽 / 按国家（含家宽）三类订阅，返回 (全量数, 家宽数)"""
    config.ensure_directories()
    residential = [n for n in verified_nodes if n["is_residential"]]
    normal = [n for n in verified_nodes if not n["is_residential"]]

    # 1. 全量总订阅
    all_links, all_proxies, all_singbox = format_node_group(verified_nodes)
    _write_b64(os.path.join(config.OUTPUT_DIR, "v2ray.txt"), all_links)
    export_clash_yaml(all_proxies, os.path.join(config.OUTPUT_DIR, "clash.yaml"))
    export_singbox_json(all_singbox, os.path.join(config.OUTPUT_DIR, "singbox.json"))

    # 2. 家宽总订阅
    res_links, res_proxies, res_singbox = format_node_group(residential, res_tag_force=True)
    _write_b64(os.path.join(config.OUTPUT_DIR, "residential.txt"), res_links)
    _write_group(os.path.join(config.OUTPUT_DIR, "residential-clash.yaml"),
                 os.path.join(config.OUTPUT_DIR, "residential-singbox.json"),
                 res_proxies, res_singbox)

    # 3. 按国家【非家宽 / 机房】
    shutil.rmtree(config.COUNTRY_DIR, ignore_errors=True)
    os.makedirs(config.COUNTRY_DIR, exist_ok=True)
    _write_by_country(normal, config.COUNTRY_DIR, res_tag_force=False)

    # 4. 按国家【真家宽】
    shutil.rmtree(config.RESIDENTIAL_COUNTRY_DIR, ignore_errors=True)
    os.makedirs(config.RESIDENTIAL_COUNTRY_DIR, exist_ok=True)
    _write_by_country(residential, config.RESIDENTIAL_COUNTRY_DIR, res_tag_force=True)

    log.info("导出完毕！全量真活 %d | 家宽真活 %d", len(all_links), len(res_links))
    return len(all_links), len(res_links)


def _write_group(clash_path: str, singbox_path: str,
                 proxies: List[Dict[str, Any]], singbox: List[Dict[str, Any]]) -> None:
    """无节点时删除陈旧产物，避免客户端拉到上一次的空壳配置"""
    if proxies:
        export_clash_yaml(proxies, clash_path)
        export_singbox_json(singbox, singbox_path)
    else:
        for p in (clash_path, singbox_path):
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass


def _write_by_country(nodes: List[Dict[str, Any]], out_dir: str, res_tag_force: bool) -> None:
    by_cc: Dict[str, List[Dict[str, Any]]] = {}
    for n in nodes:
        by_cc.setdefault(n["country"], []).append(n)
    for cc, group in by_cc.items():
        links, proxies, singbox = format_node_group(group, res_tag_force=res_tag_force)
        _write_b64(os.path.join(out_dir, f"{cc}.txt"), links)
        export_clash_yaml(proxies, os.path.join(out_dir, f"clash-{cc}.yaml"))
        export_singbox_json(singbox, os.path.join(out_dir, f"singbox-{cc}.json"))


# ---------------------------------------------------------------- meta.json

def _percentiles(values: List[int]) -> Dict[str, int]:
    if not values:
        return {"min": 0, "p50": 0, "p90": 0, "max": 0}
    ordered = sorted(values)
    def pick(p: float) -> int:
        idx = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * p))))
        return ordered[idx]
    return {"min": ordered[0], "p50": pick(0.5), "p90": pick(0.9), "max": ordered[-1]}


def write_meta(nodes: List[Dict[str, Any]], stats: Dict[str, Any],
               source_health: Optional[Dict[str, Dict[str, Any]]] = None,
               quota: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    """输出 meta.json：协议分布 / 国家分布 / 延迟分位 / 丢弃原因 / 各阶段耗时"""
    from datetime import datetime, timezone

    proto_dist = Counter(n["proto"] for n in nodes)
    country_dist = Counter(n["country"] for n in nodes)
    res_country = Counter(n["country"] for n in nodes if n["is_residential"])
    delays = [n["delay"] for n in nodes if isinstance(n.get("delay"), int)]

    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "counts": {
            "alive": len(nodes),
            "residential": sum(1 for n in nodes if n["is_residential"]),
            "countries": len(country_dist),
            "dropped_total": sum(snapshot_drops().values()),
        },
        "protocols": dict(proto_dist.most_common()),
        "countries": dict(country_dist.most_common()),
        "residential_countries": dict(res_country.most_common()),
        "quota": quota or {},
        "delay_ms": _percentiles(delays),
        "drop_reasons": dict(sorted(snapshot_drops().items(), key=lambda kv: kv[1], reverse=True)),
        "stages": stats,
        "sources": source_health or {},
    }
    config.ensure_directories()
    with open(config.META_FILE, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    log.info("元信息已写入 %s", config.META_FILE)
    return meta


# ---------------------------------------------------------------- README

def detect_repo_slug() -> Tuple[str, str]:
    """优先取 GITHUB_REPOSITORY，其次 git remote，最后 DEFAULT_REPO"""
    slug = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if not slug:
        slug = _git_remote_slug() or config.DEFAULT_REPO
    owner, _, repo = slug.partition("/")
    if not repo:
        return config.DEFAULT_REPO.split("/", 1)[0], config.DEFAULT_REPO.split("/", 1)[1]
    return owner, repo


def _git_remote_slug() -> str:
    try:
        import subprocess
        proc = subprocess.run(["git", "remote", "get-url", "origin"],
                              capture_output=True, timeout=10)
        url = (proc.stdout or b"").decode(errors="ignore").strip()
        if not url:
            return ""
        url = url.removesuffix(".git")
        if "github.com" not in url:
            return ""
        tail = url.split("github.com/", 1)[1].strip("/")
        return tail if tail.count("/") == 1 else ""
    except Exception:  # noqa: BLE001
        return ""


def _country_counts(directory: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    if not os.path.exists(directory):
        return counts
    for fn in os.listdir(directory):
        if fn.endswith(".txt"):
            cnt = _count_file(os.path.join(directory, fn))
            if cnt > 0:
                counts[fn[:-4]] = cnt
    return counts


def _country_table(counts: Dict[str, int], repo_name: str, subdir: str, cache_bust: int) -> str:
    rows: List[str] = []
    for cc in sorted(counts, key=lambda x: counts[x], reverse=True):
        flag = config.get_country_flag(cc)
        name = config.COUNTRY_NAMES.get(cc, cc)
        base_cdn = f"https://cdn.jsdelivr.net/gh/{repo_name}@main/output/{subdir}"
        base_raw = f"https://raw.githubusercontent.com/{repo_name}/main/output/{subdir}"
        col_v2 = (f"[CDN 直链]({base_cdn}/{cc}.txt?v={cache_bust}) · "
                  f"[Raw 直链]({base_raw}/{cc}.txt)")
        col_clash = (f"[CDN 直链]({base_cdn}/clash-{cc}.yaml?v={cache_bust}) · "
                     f"[Raw 直链]({base_raw}/clash-{cc}.yaml)")
        col_sb = (f"[CDN 直链]({base_cdn}/singbox-{cc}.json?v={cache_bust}) · "
                  f"[Raw 直链]({base_raw}/singbox-{cc}.json)")
        rows.append(f"| {flag} {name} | {counts[cc]} | {col_v2} | {col_clash} | {col_sb} |")
    return "\n".join(rows) if rows else "| 暂无可用节点 | 0 | - | - | - |"


_WORKER_TEMPLATE = """```javascript
export default {
  async fetch(request, env) {
    // 令牌从 Worker 环境变量读取（Settings -> Variables and Secrets -> 添加 GITHUB_PAT）
    const GITHUB_TOKEN = env.GITHUB_PAT || "";
    const OWNER = "__OWNER__";
    const REPO = "__REPO__";
    const BRANCH = "main";

    if (!GITHUB_TOKEN) {
      return new Response("Worker 未配置 GITHUB_PAT 环境变量", { status: 500 });
    }

    const url = new URL(request.url);
    const filePath = "output" + url.pathname;
    const ghUrl = "https://raw.githubusercontent.com/" + OWNER + "/" + REPO + "/" + BRANCH + "/" + filePath;

    const res = await fetch(ghUrl, {
      headers: {
        "Authorization": "token " + GITHUB_TOKEN,
        "User-Agent": "Cloudflare-Worker"
      }
    });

    if (!res.ok) {
      return new Response("Not Found", { status: 404 });
    }

    return new Response(await res.text(), {
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-cache"
      }
    });
  }
}
```"""


def _quota_line() -> str:
    """README 顶部的出库配额说明；未配置配额时返回空串"""
    quota = config.parse_country_quota()
    if not quota:
        return ""
    desc = "、".join(
        f"{config.get_country_flag(cc)} {config.COUNTRY_NAMES.get(cc, cc)} `{n}`"
        for cc, n in quota.items())
    prefer = "家宽优先、" if config.QUOTA_PREFER_RESIDENTIAL else ""
    return (f"> 🎯 **出库配额**: 仅发布 {desc}，合计上限 `{sum(quota.values())}` 个节点"
            f"（{prefer}同类按延迟升序）；其他地区及超出配额的节点不导出。  \n")


def update_readme() -> Tuple[int, int]:
    """重写 README 中的动态表格，返回 (总节点数, 家宽数)"""
    import time

    owner, repo = detect_repo_slug()
    repo_name = f"{owner}/{repo}"
    cache_bust = int(time.time())

    total_count = _count_file(os.path.join(config.OUTPUT_DIR, "v2ray.txt"))
    res_count = _count_file(os.path.join(config.OUTPUT_DIR, "residential.txt"))
    res_counts = _country_counts(config.RESIDENTIAL_COUNTRY_DIR)
    normal_counts = _country_counts(config.COUNTRY_DIR)

    cdn = f"https://cdn.jsdelivr.net/gh/{repo_name}@main/output"
    raw = f"https://raw.githubusercontent.com/{repo_name}/main/output"
    worker_code = _WORKER_TEMPLATE.replace("__OWNER__", owner).replace("__REPO__", repo)
    quota_line = _quota_line()

    content = f"""# 🚀 免费节点自动测活订阅池 (含真实家宽/住宅IP甄选)

> 👤 **定制规范命名**: 所有订阅节点均重命名为 `国旗 地区 序号 (家宽) - xiaohe`  
> ⚡ **真实可用保障**: 所有节点由 `Xray-core` 建立实际代理隧道并完成真实 HTTPS 双向传输握手，拒绝虚假通畅与死节点。无论是通过免翻 CDN 直链还是官方原生 Raw 直链拉取，节点命名格式完全一致。  
> 🧩 **协议与传输层**: 支持 vless / vmess / trojan / shadowsocks / hysteria2，覆盖 tcp、ws、grpc、httpupgrade、xhttp 传输层与 Reality 加密；QUIC / H2 / mKCP 节点经内核降级后仍可正常测活并原样导出。  
> 🔬 **双内核真实测活**: Xray-core 负责绝大多数节点；Xray 26.x 已移除内核级 hysteria2，由 sing-box 补充测活，所有入池节点均完成真实 HTTPS 双向传输握手。  
{quota_line}> ⚠️ **免责声明**: 节点均来自第三方公开渠道，本项目仅做测活与整理；节点运营方可观测经其转发的流量，请勿用于传输账号密码、密钥等敏感信息。

---

## 📌 全部节点总订阅链接

| 客户端 / 格式类型 | 节点总数 | 免翻 CDN 订阅直链 (国内直连) | 官方原生 Raw 直链 (开启代理) |
| :--- | :---: | :--- | :--- |
| 🚀 **Clash (YAML 格式)** | `{total_count}` | [🚀 免翻 CDN 直链]({cdn}/clash.yaml?v={cache_bust}) | [🌐 官方 Raw 直链]({raw}/clash.yaml) |
| ⚡ **V2RayN (Base64 格式)** | `{total_count}` | [⚡ 免翻 CDN 直链]({cdn}/v2ray.txt?v={cache_bust}) | [🌐 官方 Raw 直链]({raw}/v2ray.txt) |
| 📦 **sing-box (JSON 格式)** | `{total_count}` | [📦 免翻 CDN 直链]({cdn}/singbox.json?v={cache_bust}) | [🌐 官方 Raw 直链]({raw}/singbox.json) |

---

## 🏠 按照家宽分类节点订阅 (住宅 IP 专区)
> 经 MaxMind ASN 数据库与核心运营商白名单严格探测，排除所有云主机/数据中心及 CDN 任播，保留真实民用宽带。同一家宽出口 IP 只收录一次。

| 家宽地区 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :--- | :--- | :--- |
{_country_table(res_counts, repo_name, "residential-by-country", cache_bust)}

---

## 🗺️ 按照国家分类节点订阅 (非家宽/数据中心节点)

| 地区/国家 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :--- | :--- | :--- |
{_country_table(normal_counts, repo_name, "by-country", cache_bust)}

---

## 🔒 私有仓库（Private）无感免翻订阅方案 (基于 Cloudflare Workers)

> 如果你希望将本 GitHub 仓库设置为 **Private (私有仓库)** 保护节点资产，外部客户端无法直接拉取原生 Raw 或公共 CDN 链接，可以通过以下 Cloudflare Worker 搭建轻量级私密网关反代：

### 1. 获取 GitHub 永久个人令牌 (PAT)
1. 进入 GitHub -> **Settings** -> **Developer Settings** -> **Personal access tokens (classic)**。
2. 点击 **Generate new token (classic)**，勾选 `repo` 权限，有效期设为 `No expiration`（永不过期）。
3. 复制保存生成的以 `ghp_` 开头的 Token。

### 2. 部署 Cloudflare Worker
登录 Cloudflare Dashboard，创建一个新的 Worker，复制以下脚本粘贴并部署：

{worker_code}

### 3. 配置环境变量（切勿把令牌写进源码）
在 Worker 的 **Settings -> Variables and Secrets** 中新增变量 `GITHUB_PAT`，值为上一步的令牌，并点击 **Encrypt** 加密保存。脚本通过 `env.GITHUB_PAT` 读取。

### 4. 私有订阅链接映射方式
部署后 Worker 会分配一个专属域名（例如 `my-sub.yourname.workers.dev`），你的客户端可以直接无感订阅：
* **总 V2RayN 订阅**: `https://你的域名.workers.dev/v2ray.txt`
* **总 Clash 订阅**: `https://你的域名.workers.dev/clash.yaml`
* **总 sing-box 订阅**: `https://你的域名.workers.dev/singbox.json`
* **台湾家宽 V2RayN**: `https://你的域名.workers.dev/residential-by-country/TW.txt`
* **香港家宽 Clash**: `https://你的域名.workers.dev/residential-by-country/clash-HK.yaml`
* **日本家宽 sing-box**: `https://你的域名.workers.dev/residential-by-country/singbox-JP.json`

---

## ⭐ 项目热度

[![Star History Chart](https://api.star-history.com/svg?repos={repo_name}&type=Date)](https://star-history.com/#{repo_name}&Date)

---

## 🛠️ 项目使用说明
1. **自动更新机制**：GitHub Actions 每 6 小时全自动运行并刷新上述全部订阅与数据。
2. **多客户端兼容**：
   - **Clash / Clash Verge / Mihomo Party**：直接复制上方表格中的 **Clash 专属订阅** 链接。
   - **v2rayN / v2rayNG**：直接复制上方表格中的 **V2RayN 专属订阅** 链接。
   - **sing-box**：直接使用上方 **sing-box 专属订阅** 链接。
3. **运行统计**：每轮运行的协议分布、国家分布、延迟分位与丢弃原因见 `output/meta.json`，各节点源健康度见 `output/sources_status.json`。
"""
    with open(config.README_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    log.info("README 动态表格更新完毕！真实总节点 %d, 真实家宽 %d", total_count, res_count)
    return total_count, res_count


def print_final_report(meta: Dict[str, Any]) -> None:
    log.info("本次协议分布: %s",
             ", ".join(f"{k}={v}" for k, v in meta["protocols"].items()) or "-")
    log.info("本次国家 Top5: %s",
             ", ".join(f"{k}={v}" for k, v in list(meta["countries"].items())[:5]) or "-")
    log.info("延迟 p50=%(p50)sms p90=%(p90)sms", meta["delay_ms"])
    report_drop_stats()


# 兼容旧名
export_clash_yaml = export_clash_yaml
export_singbox_json = export_singbox_json
format_node_group = format_node_group
