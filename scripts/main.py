#!/usr/bin/env python3
"""freesub 入口：抓取 -> 解析 -> 真实测活 -> 甄别 -> 导出订阅。

原先 1400+ 行单文件已拆分到 freesub/ 包，本文件只保留 CLI 与流程编排。

用法示例：
    python scripts/main.py                     # 完整跑一轮
    python scripts/main.py --debug             # 打印每源抓取详情
    python scripts/main.py --max-candidates 500  # 只测前 500 个候选
    python scripts/main.py --dry-run           # 只跑抓取+解析，不下载内核
    python scripts/main.py --sources url1,url2   # 自定义源
"""
from __future__ import annotations

import argparse
import os
import socket
import sys
import time
from collections import Counter
from typing import Any, Dict, List, Tuple

# 支持 `python scripts/main.py`，也支持 `python -m freesub`
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from freesub import config  # noqa: E402
from freesub.classifier import classify_and_filter  # noqa: E402
from freesub.exporters import (  # noqa: E402  兼容旧引用路径
    convert_to_clash_dict, convert_to_singbox_outbound, export_clash_yaml,
    export_singbox_json, format_node_group, rename_node_link,
)
from freesub.fetcher import (  # noqa: E402
    SourceHealth, dedup_nodes, extract_nodes_from_text, fetch_all_nodes,
)
from freesub.logutil import (  # noqa: E402
    get_logger, record_drop, report_drop_stats, setup_logging,
)
from freesub.parse import (  # noqa: E402
    clear_cache, parse_node, parse_node_to_xray_outbound, strip_private_keys,
)
from freesub.prober import (  # noqa: E402
    build_batch_config as _build_batch_config,
    probe_batch as _probe_batch, probe_single_node as test_single_node_xray,
    run_probe as run_real_delay_test_xray, set_xray_binary,
    validate_config,
)
from freesub.parse import is_kernel_probeable  # noqa: E402
from freesub.prefilter import rank_candidates  # noqa: E402
from freesub.quota import CountryProgress, apply_country_quota  # noqa: E402
from freesub.reporter import (  # noqa: E402
    count_published_nodes, detect_repo_slug, export_subscriptions,
    print_final_report, update_readme, write_meta,
)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="freesub", description="免费节点自动测活订阅池",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--debug", action="store_true", help="输出每源抓取详情与调试日志")
    p.add_argument("--quiet", action="store_true", help="仅输出警告与错误")
    p.add_argument("--dry-run", action="store_true", help="只跑抓取与解析，不下载内核、不测活")
    p.add_argument("--max-candidates", type=int, default=None,
                   help=f"单次最多测活的候选节点数（默认 {config.MAX_CANDIDATES}）")
    p.add_argument("--workers", type=int, default=None,
                   help=f"并发探测线程数（默认 {config.PROBE_WORKERS}）")
    p.add_argument("--batch-size", type=int, default=None,
                   help=f"单个内核承载的节点数（默认 {config.PROBE_BATCH_SIZE}）")
    p.add_argument("--timeout", type=float, default=None,
                   help=f"单节点探测超时秒数（默认 {config.PROBE_TIMEOUT}）")
    p.add_argument("--budget", type=int, default=None,
                   help=f"测活总时间预算秒数（默认 {config.TOTAL_BUDGET_SEC}）")
    p.add_argument("--repeat", type=int, default=None,
                   help=f"单节点重复探测次数，取中位数（默认 {config.PROBE_REPEAT}）")
    p.add_argument("--sources", type=str, default=None,
                   help="逗号分隔的自定义源 URL 列表，覆盖内置源")
    p.add_argument("--country-quota", type=str, default=None,
                   help=("出库配额，形如 HK:10,US:10,JP:10,KR:10；传空字符串关闭配额 "
                         f"（默认 {config.COUNTRY_QUOTA or '关闭'}）"))
    p.add_argument("--xray", type=str, default=None, help="指定本地 xray 内核路径")
    return p


def apply_overrides(args: argparse.Namespace) -> None:
    """把 CLI 参数写回 config 模块（config 内部对象即被各模块引用）"""
    if args.max_candidates is not None:
        config.MAX_CANDIDATES = args.max_candidates
    if args.workers is not None:
        config.PROBE_WORKERS = max(1, args.workers)
    if args.batch_size is not None:
        config.PROBE_BATCH_SIZE = max(1, args.batch_size)
    if args.timeout is not None:
        config.PROBE_TIMEOUT = args.timeout
    if args.budget is not None:
        config.TOTAL_BUDGET_SEC = args.budget
    if args.repeat is not None:
        config.PROBE_REPEAT = max(1, args.repeat)
    if args.country_quota is not None:
        config.COUNTRY_QUOTA = args.country_quota


def build_candidates(raw_nodes: List[str]) -> List[tuple]:
    """把抓取到的原始链接解析为可测活的候选列表，同时统计丢弃原因"""
    candidates: List[tuple] = []
    seen: set = set()
    for raw in raw_nodes:
        outbound, server, port, proto = parse_node(raw)
        if not (outbound and server and port):
            record_drop(f"candidate_rejected:{proto}")
            continue
        key = f"{proto}://{server}:{port}"
        if key in seen:
            record_drop("candidate_duplicated")
            continue
        seen.add(key)
        candidates.append((raw, server, port, proto))
    return candidates


def split_by_kernel(candidates: List[tuple]) -> Tuple[List[tuple], List[tuple]]:
    """按内核能力分流候选节点。

    Xray 26.x 已移除内核级 hysteria2 / tuic；QUIC/H2/mKCP 传输已在解析阶段
    降级为 raw（仍可被 Xray 测活）。因此这里只有内核级 hysteria2/tuic
    会被分流到 sing-box 补充测活。
    """
    xray_items: List[tuple] = []
    sb_items: List[tuple] = []
    reasons: Counter = Counter()
    for item in candidates:
        link, _, _, proto = item
        outbound, _, _, _ = parse_node(link)
        if is_kernel_probeable(outbound):
            xray_items.append(item)
        else:
            reasons[proto] += 1
            sb_items.append(item)
    if sb_items:
        get_logger("main").info("分流至 sing-box 补充测活: %s",
                                ", ".join(f"{k}={v}" for k, v in reasons.items()))
    return xray_items, sb_items


def main(argv: List[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    log = setup_logging(debug=args.debug, quiet=args.quiet)
    apply_overrides(args)
    log = get_logger("main")

    # 只影响未显式设置超时的调用（如反向 DNS），requests 会自行覆盖
    socket.setdefaulttimeout(5.0)

    stages: Dict[str, Any] = {}
    t_all = time.time()

    t0 = time.time()
    raw_nodes, health = fetch_all_nodes(
        [u.strip() for u in args.sources.split(",") if u.strip()] if args.sources else None)
    stages["fetch_sec"] = round(time.time() - t0, 1)

    candidates = build_candidates(raw_nodes)
    log.info("格式合规候选节点数: %d", len(candidates))

    quota_map = config.parse_country_quota()
    if quota_map:
        log.info("出库配额: %s | 合计上限 %d 个",
                 ", ".join(f"{cc}={n}" for cc, n in quota_map.items()),
                 sum(quota_map.values()))
    else:
        log.info("出库配额: 未启用（发布全部存活节点）")

    if args.dry_run:
        log.info("--dry-run：跳过内核下载与测活，候选 %d 个", len(candidates))
        report_drop_stats(log)
        return 0

    from freesub import environment
    t0 = time.time()
    binary = args.xray or environment.ensure_xray()
    environment.ensure_mmdb()
    set_xray_binary(binary)
    stages["setup_sec"] = round(time.time() - t0, 1)

    previous_count = count_published_nodes()

    # 按内核能力分流：Xray 测不了的（hy2/tuic 等）交给 sing-box
    xray_candidates, sb_candidates = split_by_kernel(candidates)
    log.info("候选分流：Xray 批量 %d 个 / sing-box 补充 %d 个",
             len(xray_candidates), len(sb_candidates))

    # 配额模式：目标地区候选前置（依据链接备注的标注）+ 批次早停。
    # 3000+ 候选里目标国家占比很低（实测 HK 仅约 2%），按源顺序测得跑十几批；
    # 前置后每批都覆盖目标地区，攒够 target*factor 个存活即停。
    progress: CountryProgress | None = None
    if quota_map and xray_candidates:
        if config.PROBE_EARLY_STOP:
            xray_candidates = rank_candidates(xray_candidates, quota_map)
            progress = CountryProgress(quota_map)
            log.info("测活早停已启用：每国攒够 %s 个存活即停",
                     ", ".join(f"{cc}={v}" for cc, v in progress.need.items()))
        else:
            log.info("测活早停已关闭（PROBE_EARLY_STOP=0），候选全量测活")

    t0 = time.time()
    alive_nodes = (run_real_delay_test_xray(
        xray_candidates, progress.feed if progress else None) if xray_candidates else [])
    stages["probe_xray_sec"] = round(time.time() - t0, 1)

    if sb_candidates:
        t0 = time.time()
        from freesub import singbox
        from freesub.sbprober import run_probe as run_sb_probe, set_singbox_binary
        sb_binary = singbox.ensure_singbox()
        if sb_binary:
            set_singbox_binary(sb_binary)
            alive_nodes.extend(run_sb_probe(sb_candidates))
        else:
            log.warning("sing-box 不可用，本轮跳过 %d 个 hy2/tuic 节点", len(sb_candidates))
        stages["probe_singbox_sec"] = round(time.time() - t0, 1)

    t0 = time.time()
    verified = classify_and_filter(alive_nodes)
    stages["classify_sec"] = round(time.time() - t0, 1)

    # 出库配额：只保留目标地区，且每地区不超过上限（未配置时原样返回）
    verified, quota_report = apply_country_quota(verified)

    # 空结果保护：源站集体异常 / 网络故障时不许用空订阅覆盖线上内容。
    # 配额生效后上一版发布数就是配额总量，阈值必须取 min(上一版, 配额总量)，
    # 否则首次从 800+ 收敛到几十个时会把正常结果误判成抓取异常。
    target_total = config.quota_total()
    expected = min(previous_count, target_total) if target_total else previous_count
    if expected > 0 and len(verified) < expected * 0.5:
        log.error("本轮有效节点 %d 远低于预期 %d（<50%%），"
                  "判定为抓取或测活异常，中止导出以保留上一版订阅",
                  len(verified), expected)
        report_drop_stats(log)
        return 1

    t0 = time.time()
    export_subscriptions(verified)
    stages["export_sec"] = round(time.time() - t0, 1)
    update_readme()

    stages["total_sec"] = round(time.time() - t_all, 1)
    meta = write_meta(verified, stages, health.summary(), quota_report)
    print_final_report(meta)

    log.info("各阶段耗时: %s", ", ".join(
        f"{k}={v}s" for k, v in stages.items() if k.endswith("_sec")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
