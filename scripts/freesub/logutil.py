"""日志与丢弃原因统计。

原先全项目靠 print 输出、异常一律 except: pass 吞掉，无法回答
「这批 8000 个候选到底在哪一步、因为什么被丢掉」。这里统一：
  - logging 输出，--debug 时切到 DEBUG 级
  - record_drop() 累积丢弃计数，最后由 report_drop_stats() 汇总
"""
from __future__ import annotations

import logging
import sys
import threading
from collections import Counter
from typing import Dict

_CONFIGURED = False
_DROP_STATS: "Counter[str]" = Counter()
_STATS_LOCK = threading.Lock()

LOGGER_NAME = "freesub"


def setup_logging(debug: bool = False, quiet: bool = False) -> logging.Logger:
    """配置根 logger，重复调用只生效一次"""
    global _CONFIGURED
    logger = logging.getLogger(LOGGER_NAME)
    if _CONFIGURED:
        return logger

    level = logging.DEBUG if debug else (logging.WARNING if quiet else logging.INFO)
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    _CONFIGURED = True
    return logger


def get_logger(suffix: str = "") -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{suffix}" if suffix else LOGGER_NAME)


def record_drop(reason: str, count: int = 1) -> None:
    """记录一次丢弃（解析失败 / 协议不支持 / 插件不支持 / 超时 …）"""
    with _STATS_LOCK:
        _DROP_STATS[reason] += count


def snapshot_drops() -> Dict[str, int]:
    with _STATS_LOCK:
        return dict(_DROP_STATS)


def reset_drops() -> None:
    with _STATS_LOCK:
        _DROP_STATS.clear()


def total_dropped() -> int:
    with _STATS_LOCK:
        return sum(_DROP_STATS.values())


def report_drop_stats(logger: logging.Logger | None = None) -> Dict[str, int]:
    """打印丢弃原因汇总（按数量降序），返回快照"""
    stats = snapshot_drops()
    log = logger or get_logger()
    if not stats:
        log.info("无丢弃记录")
        return stats
    log.info("丢弃原因统计（合计 %d 个）：", sum(stats.values()))
    for reason, count in sorted(stats.items(), key=lambda kv: kv[1], reverse=True):
        log.info("    %-34s %6d", reason, count)
    return stats
