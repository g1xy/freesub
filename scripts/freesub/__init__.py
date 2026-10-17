"""freesub —— 免费节点自动测活订阅池。

模块划分：
    config      常量、可调参数、平台适配、地理/ASN 判定表
    logutil     日志与丢弃原因统计
    fetch/…     fetcher   节点源抓取、去重、源健康度
    parse       链接 -> Xray outbound（全传输层 streamSettings）
    environment 内核与 mmdb 的下载 / 缓存 / 升级
    prober      Xray 真实隧道测活（支持批次回调早停）
    classifier  出口 IP 甄别与住宅认证
    prefilter   按备注地区标注重排候选（配合早停，减少测活批次）
    quota       按国家配额截断出库节点
    exporters   Clash / sing-box 转换
    reporter    订阅文件、README、meta.json
"""
from __future__ import annotations

__all__ = [
    "classifier", "config", "environment", "exporters",
    "fetcher", "logutil", "parse", "prefilter", "prober", "quota", "reporter",
]
__version__ = "2.0.0"
