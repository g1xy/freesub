"""出口 IP 甄别与住宅属性认证。

家宽判定是一票否决式的严格逻辑：
  1. 未拿到经代理穿透的真实出网 IP -> 绝不打家宽标签
  2. 命中 Cloudflare 任播网段 -> 绝不打家宽标签
  3. 命中机房 ASN 黑名单 -> 直接排除
  4. 其余情况用 MaxMind ASN 组织名 + 反向 DNS + 运营商白名单判定
  5. 同一个物理出口 IP 在家宽池中只允许出现一次（杜绝一个 IP 刷出几十条"家宽"）

maxminddb 的 Reader 不是线程安全的（内部 seek 同一文件句柄），
因此每个工作线程独享一套 reader。
"""
from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import maxminddb

from . import config
from .exporters import to_clash_proxy
from .logutil import get_logger, record_drop

log = get_logger("classify")

_TLS = threading.local()
_ALL_READERS: List[Tuple[Any, Any]] = []
_READERS_LOCK = threading.Lock()


def _get_readers() -> Tuple[Any, Any]:
    readers = getattr(_TLS, "readers", None)
    if readers is None:
        readers = (maxminddb.open_database("Country.mmdb"),
                   maxminddb.open_database("ASN.mmdb"))
        _TLS.readers = readers
        with _READERS_LOCK:
            _ALL_READERS.append(readers)
    return readers


def _close_all_readers() -> None:
    with _READERS_LOCK:
        for country_reader, asn_reader in _ALL_READERS:
            for reader in (country_reader, asn_reader):
                try:
                    reader.close()
                except Exception:  # noqa: BLE001
                    pass
        _ALL_READERS.clear()


def _rdns_host(ip: str) -> str:
    """反向 DNS；超时由启动时统一设置的 socket.setdefaulttimeout 控制"""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host.lower()
    except Exception:  # noqa: BLE001
        return ""


def is_verified_residential(ip: str, org_str: str, asn: int) -> bool:
    if asn in config.TRUE_RESIDENTIAL_ASNS:
        return True
    info = f"{org_str} {_rdns_host(ip)}".lower()
    if any(kw in info for kw in config.IDC_KEYWORDS):
        return False
    return any(kw in info for kw in config.RESIDENTIAL_WHITELIST_KEYWORDS)


def classify_and_filter(alive_nodes: List[Tuple]) -> List[Dict[str, Any]]:
    """对存活节点做国家判定与家宽认证，并做出口 IP 级别去重"""
    verified: List[Dict[str, Any]] = []

    def classify_item(item: Tuple) -> Optional[Dict[str, Any]]:
        raw_node, server, port, proto, exit_ip, delay, is_confirmed_exit = item
        country_reader, asn_reader = _get_readers()

        country_code = "OTHER"
        try:
            c = country_reader.get(exit_ip)
            if c and "country" in c:
                code = c["country"]["iso_code"]
                if code not in ("T1", "A1", "A2", "OTHER"):
                    country_code = code.upper()
        except Exception:  # noqa: BLE001
            pass

        # 一票否决：未确认真实出口，或落在 Cloudflare 任播段
        is_residential = False
        if not is_confirmed_exit:
            record_drop("classify_unconfirmed_exit")
        elif config.is_cloudflare_cdn_ip(exit_ip):
            record_drop("classify_cloudflare_anycast")
        else:
            try:
                a = asn_reader.get(exit_ip)
                asn = a.get("autonomous_system_number", 0) if a else 0
                org = str(a.get("autonomous_system_organization", "") or "").lower() if a else ""
                if asn in config.DATACENTER_ASNS:
                    record_drop("classify_datacenter_asn")
                else:
                    is_residential = is_verified_residential(exit_ip, org, asn or 0)
            except Exception:  # noqa: BLE001
                record_drop("classify_asn_lookup_failed")

        c_dict = to_clash_proxy(raw_node, "temp")
        if not c_dict:
            record_drop(f"classify_no_clash_conversion:{proto}")
            return None

        return {
            "link": raw_node, "clash_proxy": c_dict, "country": str(country_code).upper(),
            "is_residential": is_residential, "exit_ip": exit_ip, "port": port,
            "proto": proto, "delay": delay,
        }

    log.info("解析真实出口国家并鉴定住宅属性（%d 个节点）...", len(alive_nodes))
    with ThreadPoolExecutor(max_workers=config.CLASSIFY_WORKERS) as executor:
        futures = [executor.submit(classify_item, item) for item in alive_nodes]
        for future in as_completed(futures):
            try:
                res = future.result()
            except Exception as exc:  # noqa: BLE001
                record_drop(f"classify_exception:{type(exc).__name__}")
                continue
            if res:
                verified.append(res)

    _close_all_readers()

    # 普通池保留不同配置；家宽池强制单 IP 去重，重复 IP 直接降级为普通节点
    unique_all: List[Dict[str, Any]] = []
    seen_all = set()
    seen_res_ips = set()
    for item in verified:
        link_core = item["link"].split("#")[0].strip()
        all_key = f"{item['proto']}://{item['exit_ip']}:{item['port']}_{hash(link_core)}"
        if all_key in seen_all:
            continue
        seen_all.add(all_key)

        if item["is_residential"]:
            if item["exit_ip"] in seen_res_ips:
                item["is_residential"] = False
                record_drop("classify_duplicate_residential_ip")
            else:
                seen_res_ips.add(item["exit_ip"])
        unique_all.append(item)

    verified.sort(key=lambda n: n.get("delay", 0))
    log.info("智能去重与家宽防刷完成，出库 %d 个，纯净独立家宽 %d 个",
             len(unique_all), len(seen_res_ips))
    return unique_all


# 兼容旧名
is_verified_residential_offline = is_verified_residential
get_rdns_host = _rdns_host
