"""sing-box 内核管理：专用于 Xray 26.x 不再支持的协议（hysteria2 / tuic）。

背景：Xray-core 26.x 已移除内核级 hysteria2（unknown config id: hysteria2）。
公开源里 hysteria2 节点占比约 5%（实测 5426 个去重节点中 270 个），直接丢弃
会损失一整类协议。sing-box 原生支持这些协议且已实测可完成真实 HTTPS 握手，
因此引入 sing-box 作为补充测活内核。

架构：Xray 负责绝大多数节点（批量、多入站，高吞吐）；
     sing-box 只负责 hy2/tuic 这类 Xray 测不了的节点。
"""
from __future__ import annotations

import io
import json
import os
import shutil
import tarfile
import time
import urllib.request
import zipfile
from typing import Optional, Tuple

from . import config
from .logutil import get_logger

log = get_logger("singbox")

SINGBOX_RELEASE_API = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
SINGBOX_FALLBACK_VERSION = "1.14.3"
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")


def _safe_download(url: str, timeout: int = 240) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _is_fresh(path: str, max_age_days: float) -> bool:
    if not os.path.exists(path):
        return False
    return (time.time() - os.path.getmtime(path)) / 86400.0 <= max_age_days


def _asset_name(version: str) -> str:
    """按平台选择 sing-box 官方发布包名"""
    tag = version.lstrip("v")
    suffix = "windows-amd64" if config.IS_WINDOWS else (
        "linux-amd64" if sys_platform_is_linux() else "darwin-amd64")
    ext = "zip" if config.IS_WINDOWS else "tar.gz"
    return f"sing-box-{tag}-{suffix}.{ext}"


def sys_platform_is_linux() -> bool:
    import sys
    return sys.platform.startswith("linux")


def _binary_name() -> str:
    return "sing-box.exe" if config.IS_WINDOWS else "sing-box"


def _resolve_version() -> str:
    want = config.SINGBOX_VERSION.strip()
    if want and want.lower() != "latest":
        return want.lstrip("v")
    try:
        req = urllib.request.Request(SINGBOX_RELEASE_API, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
        tag = data.get("tag_name")
        if tag:
            log.info("sing-box 最新版本: %s", tag)
            return tag.lstrip("v")
    except Exception as exc:  # noqa: BLE001
        log.warning("获取 sing-box latest 版本失败（%s），回退 %s",
                    type(exc).__name__, SINGBOX_FALLBACK_VERSION)
    return SINGBOX_FALLBACK_VERSION


def ensure_singbox() -> Optional[str]:
    """确保 sing-box 内核可用，返回路径；不可用时返回 None（调用方跳过 hy2）"""
    target = os.path.join(".", _binary_name())
    if _is_fresh(target, config.SINGBOX_MAX_AGE_DAYS):
        log.info("sing-box 内核缓存命中，路径 %s", target)
        return target

    version = _resolve_version()
    asset = _asset_name(version)
    url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/{asset}"
    log.info("下载 sing-box %s (%s)...", version, asset)
    try:
        data = _safe_download(url)
        if asset.endswith(".zip"):
            _extract_zip(data, _binary_name(), target)
        else:
            _extract_targz(data, _binary_name(), target)
        if not config.IS_WINDOWS:
            os.chmod(target, 0o755)
        _verify(target)
        log.info("sing-box 内核就绪: %s", target)
        return target
    except Exception as exc:  # noqa: BLE001
        log.warning("sing-box 下载/解压失败（%s）：%s", type(exc).__name__, exc)
        if os.path.exists(target):
            log.info("沿用已存在的 sing-box: %s", target)
            return target
        log.warning("sing-box 不可用，本轮将跳过 hy2/tuic 节点（不影响其他协议）")
        return None


def _extract_zip(data: bytes, member_suffix: str, target: str) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = [n for n in zf.namelist() if n.endswith(member_suffix)]
        if not names:
            raise RuntimeError(f"压缩包内未找到 {member_suffix}")
        with zf.open(names[0]) as src, open(target, "wb") as dst:
            shutil.copyfileobj(src, dst)


def _extract_targz(data: bytes, member_suffix: str, target: str) -> None:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        members = [m for m in tf.getmembers()
                   if m.isfile() and m.name.endswith(member_suffix)]
        if not members:
            raise RuntimeError(f"压缩包内未找到 {member_suffix}")
        src = tf.extractfile(members[0])
        if src is None:
            raise RuntimeError("解压失败")
        with src, open(target, "wb") as dst:
            shutil.copyfileobj(src, dst)


def _verify(binary: str) -> None:
    import subprocess
    proc = subprocess.run([binary, "version"], capture_output=True, timeout=30)
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode(errors="ignore")[:200]
        raise RuntimeError(f"sing-box 自检失败 (rc={proc.returncode}): {err}")
