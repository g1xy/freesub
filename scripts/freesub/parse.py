"""节点链接解析：把 vless/vmess/ss/trojan/hysteria2 链接转成 Xray outbound。

关键点：
  - 全链路只解析一次（_PARSE_CACHE），候选筛选/测活/分类/导出共用结果
  - streamSettings 覆盖 tcp/raw/ws/grpc/httpupgrade/xhttp/h2/quic/kcp 全部传输层，
    补齐原先缺失导致这类节点测活必然失败、被白白浪费预算的问题
  - 仅供 Clash/sing-box 使用的字段以 _ 前缀暂存，写内核配置前由 strip_private_keys 剔除
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import threading
import urllib.parse
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from . import config
from .logutil import record_drop

ParseResult = Tuple[Optional[Dict[str, Any]], Optional[str], Optional[int], str]

_PARSE_CACHE: Dict[str, ParseResult] = {}
_CACHE_LOCK = threading.Lock()
_CACHE_MAX = 200000

# Xray 中 network 的各种别名 -> 规范名
_NETWORK_ALIASES = {
    "tcp": "tcp", "raw": "raw", "none": "tcp",
    "ws": "ws", "websocket": "ws",
    "grpc": "grpc", "gun": "grpc",
    "h2": "http", "http": "http",
    "quic": "quic",
    "kcp": "kcp", "mkcp": "kcp",
    "httpupgrade": "httpupgrade", "splithttp": "xhttp", "xhttp": "xhttp",
}

_TLS_ALPN_KEYS = ("alpn",)


def _u(value: Optional[str], default: str = "") -> str:
    """URL 解码，失败时返回默认值"""
    if value is None:
        return default
    try:
        return urllib.parse.unquote(value)
    except Exception:
        return value


def _split_query(query: str) -> Dict[str, str]:
    return dict(re.findall(r"([^=&#]+)=([^&#]*)", query or ""))


def _norm_network(network: Optional[str]) -> str:
    return _NETWORK_ALIASES.get((network or "tcp").lower(), "tcp")


def _alpn(params: Dict[str, str]) -> List[str]:
    raw = params.get("alpn") or ""
    items = [x for x in re.split(r"[,\s]+", raw) if x]
    return items or ["h2", "http/1.1"]


# Xray 26.x 移除了 QUIC / HTTP2 / mKCP 传输（迁往 xhttp H2/H3）。
# 这些节点仍需导出给 Clash / sing-box（它们支持），因此解析时保留原始传输层
# 到 _ 前缀字段，内核侧统一降级为 raw —— 这样节点不会因为内核不支持而整类消失。
_KERNEL_TRANSPORT_FALLBACK: Dict[str, str] = {
    "http": "raw", "h2": "raw", "quic": "raw", "kcp": "raw", "mkcp": "raw",
}


def _build_transport(params: Dict[str, str], server: str) -> Optional[Dict[str, Any]]:
    """按传输层生成对应的 streamSettings 子结构。

    返回 None 表示该传输层在内核里无对应配置（应丢弃该节点）。
    """
def _build_transport(params: Dict[str, str], server: str,
                     kernel_net: Optional[str] = None,
                     original_net: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """生成 streamSettings 的传输层子结构。

    kernel_net 是**内核侧实际使用的**传输层（可能已由 h2/quic/kcp 降级为 raw），
    因此不会写出内核不认的 httpSettings / quicSettings / kcpSettings。

    降级到 raw 时必须清掉原传输层专属的 headerType —— kcp 的 headerType
    （srtp/utp/wechat-video）与 raw 的语义完全不同，误用会导致握手失败。

    返回 None 表示该传输层无法生成任何配置（应丢弃该节点）。
    """
    net = kernel_net or _norm_network(params.get("type"))
    orig = original_net or net
    host = _u(params.get("host"))
    path = _u(params.get("path"), "/")
    path = path or "/"

    if net == "ws":
        ws: Dict[str, Any] = {"path": path}
        if host:
            ws["headers"] = {"Host": host}
        return {"wsSettings": ws}

    if net == "grpc":
        service = _u(params.get("serviceName")) or _u(params.get("path")) or ""
        service = service.lstrip("/")
        grpc: Dict[str, Any] = {"serviceName": service}
        mode = (params.get("mode") or "").lower()
        if mode in ("multi", "gun"):
            grpc["multiMode"] = True
        authority = _u(params.get("authority")) or host
        if authority:
            grpc["authority"] = authority
        return {"grpcSettings": grpc}

    if net == "httpupgrade":
        hu: Dict[str, Any] = {"path": path}
        if host:
            hu["host"] = host
        return {"httpupgradeSettings": hu}

    if net == "xhttp":
        xh: Dict[str, Any] = {"path": path}
        if host:
            xh["host"] = host
        mode = params.get("mode")
        if mode:
            xh["mode"] = mode
        extra = params.get("extra")
        if extra:
            try:
                xh["extra"] = json.loads(_u(extra))
            except Exception:
                pass
        return {"xhttpSettings": xh}

    # tcp / raw：仅当指定了非 none 的 headerType 才需要额外配置
    header_type = (params.get("headerType") or "none").lower()
    # 由其他传输层降级而来时，原传输层的 headerType 对 raw 无意义，必须丢弃
    if orig not in ("tcp", "raw") and orig != net:
        header_type = "none"
    tcp: Dict[str, Any] = {"header": {"type": header_type}}
    if header_type == "http":
        hosts = [h for h in host.split(",") if h] or [server]
        tcp["header"]["request"] = {
            "version": "1.1",
            "method": "GET",
            "path": [path],
            "headers": {
                "Host": hosts,
                "User-Agent": ["Mozilla/5.0"],
                "Accept-Encoding": ["gzip, deflate"],
                "Connection": ["keep-alive"],
                "Pragma": "no-cache",
            },
        }
    return {"rawSettings": tcp}


def _build_tls_settings(params: Dict[str, str], server: str) -> Dict[str, Any]:
    """TLS 参数。

    Xray-core 26.x 已移除 allowInsecure（改为 pinnedPeerCertSha256），
    而免费节点普遍使用自签或已过期证书，无法可靠做证书固定，
    因此这里只写 serverName + alpn —— 该写法在 1.8.x 与 26.x 上均被接受。
    """
    tls: Dict[str, Any] = {"serverName": _u(params.get("sni")) or server}
    alpn = _alpn(params)
    if alpn:
        tls["alpn"] = alpn
    return tls


def _build_stream_settings(params: Dict[str, str], server: str, proto: str) -> Optional[Dict[str, Any]]:
    """组装完整 streamSettings（含 TLS / Reality），按 Xray 26.x 语义"""
    security = (params.get("security") or "none").lower()
    if proto == "trojan":
        security = "tls"
    if security not in ("none", "tls", "reality"):
        security = "none"

    original_network = _norm_network(params.get("type"))
    # 内核已移除的传输层降级为 raw，同时把原始传输层暂存给 Clash/sing-box 导出
    network = _KERNEL_TRANSPORT_FALLBACK.get(original_network, original_network)
    stream: Dict[str, Any] = {"network": network, "security": security}
    # REALITY 在 26.x 只允许 raw / xhttp / grpc，其他传输层也一并降级
    if security == "reality" and network not in config.REALITY_ALLOWED_NETWORKS:
        network = "raw"
        stream["network"] = "raw"

    if security == "reality":
        pbk = params.get("pbk", "")
        if not pbk:
            return None
        reality: Dict[str, Any] = {
            "serverName": _u(params.get("sni")) or server,
            "password": pbk,
            "shortId": params.get("sid", "") or "",
            "fingerprint": params.get("fp", "chrome") or "chrome",
        }
        if params.get("spx"):
            reality["spiderX"] = _u(params.get("spx"))
        stream["realitySettings"] = reality
    elif security == "tls":
        stream["tlsSettings"] = _build_tls_settings(params, server)

    transport = _build_transport(params, server, network, original_network)
    if transport is None:
        return None
    stream.update(transport)
    # 原始传输层暂存：内核已移除的传输层（h2/quic/kcp、reality+ws 等）
    # 在 Clash / sing-box 侧仍然有效，导出时以它为准
    if original_network != network:
        stream["_originalNetwork"] = original_network
        # kcp / quic 的 headerType、seed 等参数内核侧用不到，
        # 但客户端（Clash）需要，单独暂存
        for key in ("headerType", "seed", "quicSecurity", "key", "serviceName"):
            if params.get(key):
                stream.setdefault("_originalParams", {})[key] = params[key]
    return stream


def _truthy(value: Optional[str]) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on", "")


_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _valid_uuid(value: str) -> bool:
    """校验 vless/vmess 用户 ID

    公开源里有大量 UUID 格式错误的脏数据（如首段不足 8 位），
    内核会在解析配置时报 `encoding/hex: invalid ...` 导致**整批启动失败**，
    必须在解析阶段就拦下。
    """
    return bool(_UUID_RE.match(value or ""))


# 明确无法用于公网代理的地址：回环 / 未指定 / 组播 / 占位域名。
#
# 注意刻意**不拦私网段（10.x / 192.168.x / 172.16.x）** —— 部分机场确实用内网
# 中转出口，是否可用必须交给内核真实测活判断，在解析阶段替它下结论会造成误杀。
_BOGUS_HOSTS: FrozenSet[str] = frozenset({
    "127.0.0.1", "localhost", "0.0.0.0", "::1", "::", "example.com",
    "example.org", "your.domain.com", "test.com",
})


def _is_bogus_host(host: str) -> bool:
    """判断地址是否明显不可用（仅拦截确定性无效的，不做可达性预判）"""
    if not host:
        return True
    if host.lower() in _BOGUS_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # 域名：只排除明确的占位后缀；单段主机名交给内核判断
        return host.lower().endswith((".example", ".invalid", ".localdomain"))
    return bool(ip.is_loopback or ip.is_unspecified or ip.is_multicast)


def _host_set(node_str: str) -> Optional[str]:
    """vmess 节点：可能是域名也可能是 IP，先做合法性校验"""
    if not node_str:
        return None
    try:
        ipaddress.ip_address(node_str)
        return node_str
    except ValueError:
        return node_str if re.fullmatch(r"[A-Za-z0-9._-]+", node_str) else None


def parse_node(node_str: str) -> ParseResult:
    """带缓存的解析入口：返回 (outbound, server, port, proto)"""
    cached = _PARSE_CACHE.get(node_str)
    if cached is not None:
        return cached
    result = _parse_impl(node_str)
    with _CACHE_LOCK:
        if len(_PARSE_CACHE) < _CACHE_MAX:
            _PARSE_CACHE[node_str] = result
    return result


# 保留旧名，供既有测试与调用处使用
parse_node_to_xray_outbound = parse_node


def _parse_impl(node_str: str) -> ParseResult:
    try:
        if node_str.startswith("vless://"):
            return _parse_vless(node_str)
        if node_str.startswith("vmess://"):
            return _parse_vmess(node_str)
        if node_str.startswith("trojan://"):
            return _parse_trojan(node_str)
        if node_str.startswith("ss://"):
            return _parse_ss(node_str)
        if node_str.startswith(("hy2://", "hysteria2://")):
            return _parse_hysteria2(node_str)
    except Exception as exc:  # noqa: BLE001 - 解析失败不应中断整轮
        record_drop(f"parse_exception:{type(exc).__name__}")
        return None, None, None, "unknown"

    record_drop("parse_unrecognized_link")
    return None, None, None, "unknown"


def _parse_vless(node_str: str) -> ParseResult:
    m = re.search(r"vless://([^@]+)@([^:]+):(\d+)\??(.*)", node_str)
    if not m:
        record_drop("vless_bad_structure")
        return None, None, None, "vless"
    uuid_str, server, port_s, query = m.groups()
    params = _split_query(query)
    if not _valid_uuid(uuid_str):
        record_drop("vless_invalid_uuid")
        return None, None, None, "vless"
    if _is_bogus_host(server):
        record_drop(f"vless_bogus_host:{server[:24]}")
        return None, None, None, "vless"
    stream = _build_stream_settings(params, server, "vless")
    if stream is None:
        record_drop("vless_missing_reality_pbk" if params.get("security") == "reality" else "vless_unsupported_transport")
        return None, None, None, "vless"

    user: Dict[str, Any] = {"id": uuid_str, "encryption": params.get("encryption", "none")}
    # Xray 26.x 校验 flow：
    #   - security=none 时带 flow 会报 `VLESS users: "flow" doesn't support "none"`
    #   - flow 值为 "none" 本身也不被接受（源里存在 `flow=none` 的写法）
    # 两种情况都会让**整批**配置启动失败，必须在解析阶段剔除。
    flow = (params.get("flow") or "").strip()
    if flow and flow.lower() != "none" and stream.get("security") in ("tls", "reality"):
        user["flow"] = flow

    outbound = {
        "protocol": "vless",
        "settings": {"vnext": [{"address": server, "port": int(port_s), "users": [user]}]},
        "streamSettings": stream,
    }
    return outbound, server, int(port_s), "vless"


def _parse_vmess(node_str: str) -> ParseResult:
    b64 = node_str[8:].split("#")[0].strip()
    b64 += "=" * (-len(b64) % 4)
    # 去掉 base64 里可能出现的换行/空白（部分源会把长链接折行）
    b64 = re.sub(r"\s+", "", b64)
    try:
        data = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
    except Exception:  # noqa: BLE001
        record_drop("vmess_bad_base64")
        return None, None, None, "vmess"
    if not isinstance(data, dict):
        record_drop("vmess_bad_json_shape")
        return None, None, None, "vmess"
    server = str(data.get("add", "")).strip()
    port = int(data.get("port", 0) or 0)
    uuid_str = str(data.get("id", "")).strip()
    server = _host_set(server)
    if not server or port <= 0 or not uuid_str:
        record_drop("vmess_missing_address_or_id")
        return None, None, None, "vmess"
    if not _valid_uuid(uuid_str):
        record_drop("vmess_invalid_uuid")
        return None, None, None, "vmess"
    if _is_bogus_host(server):
        record_drop(f"vmess_bogus_host:{server[:24]}")
        return None, None, None, "vmess"

    is_tls = str(data.get("tls", "")).lower() in ("tls", "1", "true")
    params = {
        "type": str(data.get("net", "tcp")),
        "host": str(data.get("host", "")).strip(),
        "path": str(data.get("path", "") or "/"),
        "security": "tls" if is_tls else "none",
        "sni": str(data.get("sni", "")).strip() or str(data.get("host", "")).strip(),
        "serviceName": str(data.get("path", "")) if str(data.get("net", "")).lower() == "grpc" else "",
        "headerType": str(data.get("type", "none")),
        "seed": str(data.get("seed", "")),
    }
    stream = _build_stream_settings(params, server, "vmess")
    if stream is None:
        record_drop("vmess_unsupported_transport")
        return None, None, None, "vmess"

    outbound = {
        "protocol": "vmess",
        "settings": {"vnext": [{"address": server, "port": port, "users": [{
            "id": uuid_str,
            "alterId": int(data.get("aid", 0) or 0),
            "security": data.get("scy") or data.get("security") or "auto",
        }]}]},
        "streamSettings": stream,
    }
    return outbound, server, port, "vmess"


def _parse_trojan(node_str: str) -> ParseResult:
    m = re.search(r"trojan://([^@]+)@([^:]+):(\d+)\??(.*)", node_str)
    if not m:
        record_drop("trojan_bad_structure")
        return None, None, None, "trojan"
    password, server, port_s, query = m.groups()
    params = _split_query(query)
    if _is_bogus_host(server):
        record_drop(f"trojan_bogus_host:{server[:24]}")
        return None, None, None, "trojan"
    stream = _build_stream_settings(params, server, "trojan")
    if stream is None:
        record_drop("trojan_unsupported_transport")
        return None, None, None, "trojan"

    outbound = {
        "protocol": "trojan",
        "settings": {"servers": [{"address": server, "port": int(port_s), "password": password}]},
        "streamSettings": stream,
    }
    return outbound, server, int(port_s), "trojan"


def _decode_userinfo(userinfo: str) -> Tuple[str, str]:
    """解码 ss 链接的 userinfo，返回 (解码结果, 状态)

    状态取值：ok / plaintext / undecodable

    SIP002 有两种写法：明文 `method:password` 与整体 base64。
    旧实现无条件先 base64decode，明文形态会被解成二进制垃圾并当作 cipher
    （线上可见 cipher 形如 'ywvzlti1ni1ny206...'），导致好节点被白名单误杀。

    userinfo 常带 URL 编码（如 '%3D' 表示 '='），必须先 unquote 再解码。
    """
    userinfo = _u(userinfo)
    if ":" in userinfo:
        return userinfo, "plaintext"
    for candidate in (_b64_text(userinfo), _b64_text(userinfo.replace("-", "+").replace("_", "/"))):
        if ":" in candidate:
            return candidate, "ok"
    return "", "undecodable"


def _b64_text(text: str) -> str:
    """尝试把 base64 文本解成 UTF-8 字符串，失败返回空串"""
    try:
        padded = text + "=" * (-len(text) % 4)
        return base64.b64decode(padded).decode("utf-8", errors="ignore")
    except Exception:  # noqa: BLE001
        return ""


def _parse_ss(node_str: str) -> ParseResult:
    raw = node_str[5:].split("#")[0].strip()
    server, port, password, cipher = "", 0, "", ""
    plugin_param = ""
    if "?" in raw:
        raw, _, qs = raw.partition("?")
        plugin_param = _u(_split_query(qs).get("plugin", ""))

    if "@" in raw:
        user_info, host_info = raw.rsplit("@", 1)
        decoded, status = _decode_userinfo(user_info)
        if status == "undecodable":
            # 解析不出 cipher:password 的链接是损坏数据，不要把整段密文当 cipher
            record_drop("ss_userinfo_undecodable")
            return None, None, None, "ss"
        if ":" in decoded:
            cipher, password = decoded.split(":", 1)
        host_info = _u(host_info)
        if ":" in host_info:
            host, _, port_s = host_info.split("?")[0].split("/", 1)[0].rpartition(":")
            if port_s:
                server, port = host, int(port_s)
    else:
        decoded = _b64_text(_u(raw))
        if "@" in decoded:
            user_info, host_info = decoded.rsplit("@", 1)
            if ":" in user_info:
                cipher, password = user_info.split(":", 1)
            if ":" in host_info:
                host, _, port_s = host_info.split("?")[0].split("/", 1)[0].rpartition(":")
                if port_s:
                    server, port = host, int(port_s)

    server = _host_set(server)
    if not server or port <= 0:
        record_drop("ss_bad_structure")
        return None, None, None, "ss"
    if _is_bogus_host(server):
        record_drop(f"ss_bogus_host:{server[:24]}")
        return None, None, None, "ss"

    cipher = (cipher or "chacha20-ietf-poly1305").strip().lower()
    # 解码失败时 cipher 仍可能是密文残留，这类节点无法确定加密方式，直接丢弃
    if not cipher.isascii() or ":" in cipher or len(cipher) > 32:
        record_drop("ss_cipher_unresolvable")
        return None, None, None, "ss"
    # 启用 cipher 白名单：内核不支持的加密方式必然握手失败，提前丢弃
    if cipher not in config.VALID_SS_CIPHERS:
        record_drop(f"ss_unsupported_cipher:{cipher}")
        return None, None, None, "ss"

    # 内核不支持 shadowsocks 插件，真实测活不可能通过，直接丢弃而非白跑
    plugin_name = plugin_param.split(";")[0].strip().lower() if plugin_param else ""
    plugin_name = _u(plugin_name)
    if plugin_name and any(plugin_name.startswith(p) for p in config.SS_PLUGIN_PREFIXES):
        record_drop(f"ss_plugin_unsupported:{plugin_name}")
        return None, None, None, "ss"
    if plugin_param and not plugin_name:
        record_drop("ss_plugin_unparsable")
        return None, None, None, "ss"

    outbound = {
        "protocol": "shadowsocks",
        "settings": {"servers": [{
            "address": server, "port": port,
            "method": cipher, "password": password,
        }]},
    }
    return outbound, server, port, "ss"


def _parse_hysteria2(node_str: str) -> ParseResult:
    prefix = "hy2://" if node_str.startswith("hy2://") else "hysteria2://"
    raw = node_str[len(prefix):].split("#")[0]
    m = re.search(r"([^@]+)@([^:/?#]+):(\d+)", raw)
    if not m:
        record_drop("hy2_bad_structure")
        return None, None, None, "hysteria2"
    auth, server, port_s = m.groups()
    q_pos = raw.find("?")
    params = _split_query(raw[q_pos + 1:]) if q_pos != -1 else {}
    server = _host_set(server)
    if not server or _is_bogus_host(server):
        record_drop(f"hy2_bogus_host:{str(server)[:24]}")
        return None, None, None, "hysteria2"

    params = {k: _u(v) for k, v in params.items()}
    alpn_raw = params.get("alpn", "") or ""
    alpn = [a for a in re.split(r"[,\s]+", alpn_raw) if a] or ["h3"]

    outbound = {
        "protocol": "hysteria2",
        "settings": {"servers": [{"address": server, "port": int(port_s), "password": auth}]},
        "streamSettings": {
            "network": "tcp",  # hy2 走 UDP/QUIC，内核按独立协议处理
            "security": "tls",
            # 与 _build_tls_settings 同理：Xray 26.x 已移除 allowInsecure
            "tlsSettings": {
                "serverName": params.get("sni") or server,
                "alpn": alpn,
            },
        },
    }
    # obfs 不参与 Xray 内核（版本差异大，未知字段会导致启动失败），
    # 仅以 _ 前缀暂存，供 Clash / sing-box 导出使用
    if params.get("obfs"):
        outbound["_hy_obfs"] = {"type": params["obfs"], "password": params.get("obfs-password", "")}
    return outbound, server, int(port_s), "hysteria2"


def strip_private_keys(outbound: Dict[str, Any]) -> Dict[str, Any]:
    """剔除仅供 Clash/sing-box 导出使用的 _ 前缀暂存字段，避免内核因未知字段启动失败"""
    return {k: v for k, v in outbound.items() if not k.startswith("_")}


# 兼容旧名
_strip_private_keys = strip_private_keys


def is_kernel_probeable(outbound: Optional[Dict[str, Any]]) -> bool:
    """该 outbound 能否交给 Xray 内核做真实测活。

    注意：QUIC / H2 / mKCP 传输已在 `_build_stream_settings` 阶段降级为 raw，
    并把原值暂存到 `_originalNetwork` 供 Clash/sing-box 导出使用；26.x 已移除的
    ss cipher 已在解析阶段直接丢弃。因此这里只剩两类不可测活项：

      - 内核级 hysteria2 / tuic（26.x 返回 unknown config id）-> 交给 sing-box
      - REALITY 配了内核不接受的传输层（parse 已降级，这里是兜底）
    """
    if not outbound:
        return False
    if outbound.get("protocol") in config.KERNEL_UNSUPPORTED_PROTOCOLS:
        return False
    stream = outbound.get("streamSettings") or {}
    if stream.get("security") == "reality" and \
            stream.get("network") not in config.REALITY_ALLOWED_NETWORKS:
        return False
    return True


def kernel_incompatibility(outbound: Optional[Dict[str, Any]]) -> str:
    """返回该 outbound 的内核兼容性问题描述（无问题返回空串）"""
    if not outbound:
        return "parse_failed"
    if outbound.get("protocol") in config.KERNEL_UNSUPPORTED_PROTOCOLS:
        return f"kernel_unsupported_protocol:{outbound['protocol']}"
    stream = outbound.get("streamSettings") or {}
    network = stream.get("network")
    if stream.get("security") == "reality" and \
            network not in config.REALITY_ALLOWED_NETWORKS:
        return f"reality_unsupported_network:{network}"
    return ""


def clear_cache() -> None:
    with _CACHE_LOCK:
        _PARSE_CACHE.clear()
