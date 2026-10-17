"""候选优先级重排：利用链接自带的地区标注把目标地区候选前置。

为什么需要它
------------
配额模式下只需要每国几个节点，但公开源里目标国家占比很低（实测 820 个
已甄别节点中 HK 仅 17 个）。若按源顺序测活，要凑够 10 个 HK 得把 3000+
候选几乎测完（17 批、约 8 分钟）。

唯一可靠的先验是链接备注里的地区标注（`#香港 01`、vmess 的 `ps`）：
  - 目标国家节点的标注覆盖率实测 100%（HK 8/8、US 143/143、JP 55/55、KR 22/22）
  - 按备注统计的国家分布与 meta.json 的真实出口分布逐国完全相同（本批源）
所以把目标地区候选前置 + 轮转交错，再配合批次早停，通常 2~3 批即可收工。

注意：**不要**用 server 地址的 GeoIP 分组 —— 实测 server 地区与真实出口
国家仅 22.8% 重合（大量中转/CDN 落地），按它筛会把 HK 候选筛没。

排序只影响"先测谁"，不改变最终挑选（仍是配额 + 家宽优先 + 延迟升序），
所以标注误判不会导致错误出库，最坏情况是多测几批。
"""
from __future__ import annotations

import base64
import json
import re
import urllib.parse
from typing import Dict, List

from . import config
from .logutil import get_logger

log = get_logger("prefilter")

NodeTuple = tuple


def _extract_remark(link: str) -> str:
    """取链接备注：vmess 读 base64 里的 ps，其余读 # 之后（URL 解码）"""
    try:
        if link.startswith("vmess://"):
            b64 = link[8:]
            b64 += "=" * (-len(b64) % 4)
            data = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
            return str(data.get("ps") or "")
        if "#" in link:
            return urllib.parse.unquote(link.split("#", 1)[1])
    except Exception:  # noqa: BLE001
        return ""
    return ""


def _match_keyword(text: str, kw: str) -> bool:
    """ASCII 缩写要求前后不紧邻字母（`HK01` 命中、`plus`/`RUS` 不命中）"""
    if kw.isascii():
        return re.search(rf"(?<![a-z]){re.escape(kw)}(?![a-z])", text) is not None
    return kw in text


def detect_region_hint(link: str) -> str:
    """从备注猜国家代码；无标注或命中多个地区时返回空串（不参与前置）"""
    remark = _extract_remark(link)
    if not remark:
        return ""
    text = remark.lower()
    hits = [cc for cc, kws in config.REGION_HINTS.items()
            if any(_match_keyword(text, kw) for kw in kws)]
    return hits[0] if len(hits) == 1 else ""


def rank_candidates(candidates: List[NodeTuple],
                    quota: Dict[str, int]) -> List[NodeTuple]:
    """把标注为配额地区的候选前置并轮转交错，其余候选保持原序排在后面。

    轮转（HK,US,JP,KR,HK,US,…）保证每个批次都覆盖所有目标地区，
    早停才不会被"前几批恰好全是 US"拖住。
    """
    if not quota:
        return list(candidates)

    buckets: Dict[str, List[NodeTuple]] = {cc: [] for cc in quota}
    rest: List[NodeTuple] = []
    for item in candidates:
        cc = detect_region_hint(item[0])
        if cc in buckets:
            buckets[cc].append(item)
        else:
            rest.append(item)

    ordered: List[NodeTuple] = []
    positions = {cc: 0 for cc in buckets}
    while True:
        progressed = False
        for cc in buckets:
            pos = positions[cc]
            if pos < len(buckets[cc]):
                ordered.append(buckets[cc][pos])
                positions[cc] = pos + 1
                progressed = True
        if not progressed:
            break

    detail = ", ".join(f"{cc}={len(v)}" for cc, v in buckets.items())
    log.info("按地区标注重排候选：命中目标 %d 个（%s），其余 %d 个后置",
             len(ordered), detail, len(rest))
    return ordered + rest
