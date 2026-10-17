"""出库配额：只发布指定国家/地区的固定数量节点。

公开源单轮通常能活下来几百上千个节点，全量发布对客户端并不友好
（首连测速慢、列表难翻），也让订阅面被放大。配额层在
「分类甄别完成之后、导出之前」按国家截断：

  - 配额外的国家整体不导出（记 quota_country_excluded:<CC>）
  - 配额内按 QUOTA_PREFER_RESIDENTIAL 决定是否家宽优先，同类按延迟升序
  - 超出配额的节点丢弃并记 quota_overflow:<CC>

调用方必须使用返回的列表继续导出，否则截断不生效。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from . import config
from .logutil import get_logger, record_drop

log = get_logger("quota")

_MISSING_DELAY = 99999


def _pick_key(item: Dict[str, Any]) -> Tuple[int, int]:
    """家宽优先（可关），同类按延迟升序；缺延迟的排到最后"""
    delay = item.get("delay")
    delay = delay if isinstance(delay, int) else _MISSING_DELAY
    tier = 0 if item.get("is_residential") else 1
    return (tier, delay) if config.QUOTA_PREFER_RESIDENTIAL else (0, delay)


def apply_country_quota(
    nodes: List[Dict[str, Any]],
    quota: Optional[Dict[str, int]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, int]]]:
    """按国家配额截断节点，返回 (保留节点, 每地区明细)。

    配额为空（未配置/配置非法）时原样返回，明细为空 dict。
    保留顺序 = 配额声明顺序 + 组内挑选顺序，保证订阅里编号分段连续。
    """
    quota_map = config.parse_country_quota() if quota is None else dict(quota)
    if not quota_map:
        return list(nodes), {}

    buckets: Dict[str, List[Dict[str, Any]]] = {cc: [] for cc in quota_map}
    excluded: Dict[str, int] = {}
    for item in nodes:
        cc = str(item.get("country") or "OTHER").upper()
        if cc in buckets:
            buckets[cc].append(item)
        else:
            excluded[cc] = excluded.get(cc, 0) + 1
    for cc, count in excluded.items():
        record_drop(f"quota_country_excluded:{cc}", count)

    chosen: List[Dict[str, Any]] = []
    report: Dict[str, Dict[str, int]] = {}
    for cc, limit in quota_map.items():
        pool = sorted(buckets[cc], key=_pick_key)
        picked = pool[:limit]
        overflow = len(pool) - len(picked)
        if overflow > 0:
            record_drop(f"quota_overflow:{cc}", overflow)
        report[cc] = {
            "target": limit,
            "available": len(pool),
            "selected": len(picked),
            "residential": sum(1 for n in picked if n.get("is_residential")),
        }
        if len(picked) < limit:
            log.warning("配额未满：%s 目标 %d、实际 %d（本轮该地区可用仅 %d）",
                        cc, limit, len(picked), len(pool))
        chosen.extend(picked)

    detail = ", ".join(f"{cc}={v['selected']}/{v['target']}" for cc, v in report.items())
    if excluded:
        drop_detail = ", ".join(f"{cc}={n}" for cc, n in
                                sorted(excluded.items(), key=lambda kv: kv[1], reverse=True))
        log.info("非配额地区未发布: %s", drop_detail)
    log.info("出库配额截断: %s | 合计 %d/%d（家宽 %d）",
             detail, len(chosen), sum(quota_map.values()),
             sum(v["residential"] for v in report.values()))
    return chosen, report
