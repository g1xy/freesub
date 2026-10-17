"""freesub —— 免费节点自动测活订阅池。

模块划分：
    config      常量、可调参数、平台适配、地理/ASN 判定表
    logutil     日志与丢弃原因统计
    fetch/…     fetcher   节点源抓取、去重、源健康度
    parse       链接 -> Xray outbound（全传输层 streamSettings）
    environment 内核与 mmdb 的下载 / 缓存 / 升级
    prober      Xray 真实隧道测活
    classifier  出口 IP 甄别与住宅认证
    exporters   Clash / sing-box 转换
    reporter    订阅文件、README、meta.json
"""
from __future__ import annotations

__all__ = [
    "classifier", "config", "environment", "exporters",
    "fetcher", "logutil", "parse", "prober", "reporter",
]
__version__ = "2.0.0"
