"""Xray-core 管理：下载 / 缓存 / 版本解析 / 自检。

Xray 26.x 的能力边界（由真实二进制 xray run -test 逐项实测，见 OPTIMIZATION.md）：
  - 不再注册内核级 hysteria2 / tuic（unknown config id）
  - 不再支持 QUIC / HTTP2(h2) / mKCP 传输
  - REALITY 仅允许搭配 raw / xhttp / grpc
  - allowInsecure 已移除（改为 pinnedPeerCertSha256）
  - ss cipher 仅剩 aes-*-gcm / chacha20-ietf-poly1305 / xchacha20-ietf-poly1305 / none
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import time
import urllib.request
import zipfile
from typing import Optional, Tuple

from . import config
from .logutil import get_logger

log = get_logger("env")

FALLBACK_XRAY_VERSION = "v1.8.24"
COUNTRY_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
ASN_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"
XRAY_RELEASE_API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")


def _safe_download(url: str, dest_path: str, timeout: int = 180) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "*/*"})
    tmp = dest_path + ".part"
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp, "wb") as out:
        shutil.copyfileobj(resp, out)
    os.replace(tmp, dest_path)


def _is_fresh(path: str, max_age_days: float) -> bool:
    """文件存在且未过期才算命中缓存。

    注意不能用 `age <= max_age`：文件不存在时 age 为 inf，而 `max_age <= inf`
    恒为 True，会把「缺失」误判为「新鲜」从而跳过下载（CI 缓存未命中时致命）。
    """
    if not os.path.exists(path):
        return False
    return (time.time() - os.path.getmtime(path)) / 86400.0 <= max_age_days


def _resolve_xray_version() -> str:
    """解析要使用的 xray 版本；latest 走 GitHub API，失败回退固定版本"""
    want = config.XRAY_VERSION.strip()
    if want and want.lower() != "latest":
        return want if want.startswith("v") else f"v{want}"
    try:
        req = urllib.request.Request(XRAY_RELEASE_API, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
        tag = data.get("tag_name")
        if tag:
            log.info("xray-core 最新版本: %s", tag)
            return tag
    except Exception as exc:  # noqa: BLE001
        log.warning("获取 xray latest 版本失败（%s），回退 %s",
                    type(exc).__name__, FALLBACK_XRAY_VERSION)
    return FALLBACK_XRAY_VERSION


def ensure_xray() -> str:
    """确保本地存在可用 xray 内核，返回可执行文件路径"""
    target = os.path.join(".", config.XRAY_BIN)

    if _is_fresh(target, config.XRAY_MAX_AGE_DAYS):
        age = (time.time() - os.path.getmtime(target)) / 86400.0
        log.info("xray 内核缓存命中（%.1f 天前），路径 %s", age, target)
        return target

    version = _resolve_xray_version()
    asset = config._xray_asset_name()
    url = f"https://github.com/XTLS/Xray-core/releases/download/{version}/{asset}"
    log.info("下载 Xray-core %s (%s)...", version, asset)

    zip_path = "xray.zip"
    try:
        _safe_download(url, zip_path)
        member = config.xray_archive_member()
        with zipfile.ZipFile(zip_path) as zf:
            with zf.open(member) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
        _make_executable(target)
        _verify_xray(target)
        log.info("xray 内核就绪: %s", target)
    except Exception as exc:  # noqa: BLE001
        log.warning("xray 下载/解压失败（%s）", exc)
        if os.path.exists(target):
            log.info("沿用已存在的内核: %s", target)
        else:
            raise
    finally:
        if os.path.exists(zip_path):
            try:
                os.remove(zip_path)
            except OSError:
                pass
    return target


def _make_executable(path: str) -> None:
    if config.IS_WINDOWS:
        return
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _verify_xray(binary: str) -> None:
    """跑一次 version 命令，确认二进制真的可执行（架构不匹配会在这里暴露）"""
    import subprocess
    proc = subprocess.run([binary, "version"], capture_output=True, timeout=30)
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode(errors="ignore")[:200]
        raise RuntimeError(f"xray 自检失败 (rc={proc.returncode}): {err}")


def ensure_mmdb() -> None:
    """确保两个 mmdb 就绪；缺失或超过 MMDB_MAX_AGE_DAYS 才重下"""
    for url, name in ((COUNTRY_URL, "Country.mmdb"), (ASN_URL, "ASN.mmdb")):
        if _is_fresh(name, config.MMDB_MAX_AGE_DAYS):
            age = (time.time() - os.path.getmtime(name)) / 86400.0
            log.info("%s 缓存命中（%.1f 天前）", name, age)
            continue
        log.info("下载 %s...", name)
        try:
            _safe_download(url, name)
        except Exception as exc:  # noqa: BLE001
            if os.path.exists(name):
                log.warning("%s 下载失败（%s），沿用本地旧库", name, exc)
            else:
                raise


def setup() -> Tuple[str, str, str]:
    """准备内核与数据库，返回 (xray_bin, country_mmdb, asn_mmdb)"""
    log.info("准备 Xray-core 内核与 MaxMind 数据库...")
    binary = ensure_xray()
    ensure_mmdb()
    return binary, "Country.mmdb", "ASN.mmdb"
