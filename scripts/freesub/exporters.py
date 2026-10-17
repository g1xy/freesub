"""客户端格式导出：Clash(YAML) / V2RayN(Base64) / sing-box(JSON)。

三份产物必须对同一节点给出语义等价的配置——原先 sing-box 只写 selector/urltest
引用不存在的 tag，且三端对新传输层的映射各不相同，这里统一由 parse 层
产出的 streamSettings 派生。
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

import yaml

from . import config
from .parse import parse_node, strip_private_keys

# ---------------------------------------------------------------- Clash 侧

_CLASH_TRANSPORT_MAP = {
    "ws": "ws", "grpc": "grpc", "httpupgrade": "httpupgrade",
    "xhttp": "xhttp", "http": "http", "quic": "quic", "kcp": "kcp", "tcp": "tcp",
}


def _clash_ws_opts(stream: Dict[str, Any]) -> Dict[str, Any]:
    ws = stream.get("wsSettings", {})
    opts: Dict[str, Any] = {"path": ws.get("path", "/")}
    headers = ws.get("headers") or {}
    if headers.get("Host"):
        opts["headers"] = {"Host": headers["Host"]}
    return opts


def _clash_transport(stream: Dict[str, Any]) -> Dict[str, Any]:
    """把 Xray streamSettings 翻译为 Clash 的 network / xxx-opts 字段

    stream 里可能带 `_originalNetwork`（内核已移除的传输层在 parse 阶段被降级
    为 raw）。Clash 支持这些传输层，导出时必须用原值，否则节点会被配错。
    """
    net = stream.get("_originalNetwork") or stream.get("network", "tcp")
    clash_net = _CLASH_TRANSPORT_MAP.get(net)
    out: Dict[str, Any] = {}
    if not clash_net:
        return out

    if net == "ws":
        out["network"] = "ws"
        out["ws-opts"] = _clash_ws_opts(stream)
    elif net == "grpc":
        grpc = stream.get("grpcSettings", {})
        out["network"] = "grpc"
        out["grpc-opts"] = {
            "grpc-service-name": grpc.get("serviceName", ""),
            **({"grpc-authority": grpc["authority"]} if grpc.get("authority") else {}),
        }
        if grpc.get("multiMode"):
            out["grpc-opts"]["grpc-multi-mode"] = True
    elif net == "httpupgrade":
        hu = stream.get("httpupgradeSettings", {})
        out["network"] = "httpupgrade"
        out["httpupgrade-opts"] = {"path": hu.get("path", "/")}
        if hu.get("host"):
            out["httpupgrade-opts"]["host"] = hu["host"]
    elif net == "xhttp":
        xh = stream.get("xhttpSettings", {})
        out["network"] = "xhttp"
        out["xhttp-opts"] = {"path": xh.get("path", "/")}
        if xh.get("host"):
            out["xhttp-opts"]["host"] = xh["host"]
        if xh.get("mode"):
            out["xhttp-opts"]["mode"] = xh["mode"]
    elif net == "http":
        http = stream.get("httpSettings", {})
        out["network"] = "http"
        out["http-opts"] = {"path": [http.get("path", "/")]}
        if http.get("host"):
            out["http-opts"]["headers"] = {"Host": http["host"]}
    elif net == "quic":
        quic = stream.get("quicSettings") or {}
        orig = stream.get("_originalParams") or {}
        out["network"] = "quic"
        out["quic-opts"] = {
            "quic-security": quic.get("security") or orig.get("quicSecurity") or "none",
        }
    elif net == "kcp":
        kcp = stream.get("kcpSettings") or {}
        orig = stream.get("_originalParams") or {}
        header = (kcp.get("header") or {}).get("type") or orig.get("headerType") or "none"
        out["network"] = "kcp"
        out["kcp-opts"] = {"header": {"type": str(header).lower()}}
        if orig.get("seed"):
            out["kcp-opts"]["seed"] = orig["seed"]

    if net in ("tcp", "raw"):
        # Clash 的 tcp-over-http 需要完整的 http-opts 三元组，从内核配置里回读 host/path
        raw = stream.get("rawSettings", {})
        header = raw.get("header") or {}
        if header.get("type") == "http":
            request = header.get("request") or {}
            hosts = (request.get("headers") or {}).get("Host") or []
            paths = request.get("path") or ["/"]
            out["network"] = "tcp"
            out["http-opts"] = [request.get("method", "GET"), paths[0],
                                {"Host": hosts or [""]}]
    return out

def to_clash_proxy(node_str: str, name: str) -> Optional[Dict[str, Any]]:
    """节点链接 -> Clash proxy dict（失败返回 None）"""
    outbound, server, port, proto = parse_node(node_str)
    if not outbound:
        return None
    stream = outbound.get("streamSettings", {}) or {}
    sec = stream.get("security")

    base: Dict[str, Any] = {"name": name, "server": server, "port": port, "udp": True}
    try:
        if proto == "vless":
            user = outbound["settings"]["vnext"][0]["users"][0]
            proxy: Dict[str, Any] = {
                **base, "type": "vless", "uuid": user["id"],
                "tls": sec in ("tls", "reality"), "skip-cert-verify": True,
            }
            if user.get("flow"):
                proxy["flow"] = user["flow"]
            if sec == "reality":
                r = stream.get("realitySettings", {})
                proxy["reality-opts"] = {
                    "public-key": r.get("password") or r.get("publicKey", "")
                }
                proxy["servername"] = r.get("serverName", server)
                proxy["client-fingerprint"] = r.get("fingerprint", "chrome")
            elif sec == "tls":
                proxy["servername"] = stream.get("tlsSettings", {}).get("serverName", server)
        elif proto == "vmess":
            user = outbound["settings"]["vnext"][0]["users"][0]
            proxy = {
                **base, "type": "vmess", "uuid": user["id"],
                "alterId": user.get("alterId", 0), "cipher": user.get("security", "auto"),
                "tls": sec == "tls", "skip-cert-verify": True,
            }
            if sec == "tls":
                proxy["servername"] = stream.get("tlsSettings", {}).get("serverName", server)
        elif proto == "trojan":
            srv = outbound["settings"]["servers"][0]
            proxy = {
                **base, "type": "trojan", "password": srv["password"],
                "sni": stream.get("tlsSettings", {}).get("serverName", server),
                "skip-cert-verify": True,
            }
        elif proto == "ss":
            srv = outbound["settings"]["servers"][0]
            proxy = {**base, "type": "ss", "cipher": srv["method"], "password": srv["password"]}
        elif proto == "hysteria2":
            srv = outbound["settings"]["servers"][0]
            tls = stream.get("tlsSettings", {})
            proxy = {
                **base, "type": "hysteria2", "password": srv["password"],
                "sni": tls.get("serverName", server), "alpn": tls.get("alpn", ["h3"]),
                "skip-cert-verify": True,
            }
            obfs = outbound.get("_hy_obfs")
            if obfs:
                proxy["obfs"] = obfs["type"]
                proxy["obfs-password"] = obfs["password"]
        else:
            return None

        # hysteria2 不接受 network 字段（内核以独立协议处理传输层）
        if proto != "hysteria2":
            proxy.update(_clash_transport(stream))
        return proxy
    except Exception:
        return None


# ---------------------------------------------------------------- sing-box 侧

def _singbox_transport(stream: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """sing-box 侧同样优先使用原始传输层（内核已移除的那些 sing-box 仍支持）"""
    net = stream.get("_originalNetwork") or stream.get("network", "tcp")
    orig = stream.get("_originalParams") or {}
    if net in ("tcp", "raw"):
        header_type = (stream.get("rawSettings", {}).get("header") or {}).get("type", "none")
        return {"type": "http", "host": [], "path": "/"} if header_type == "http" else None
    if net == "ws":
        ws = stream.get("wsSettings", {})
        return {"type": "ws", "path": ws.get("path", "/"), "headers": ws.get("headers") or {}}
    if net == "grpc":
        grpc = stream.get("grpcSettings", {})
        return {"type": "grpc",
                "service_name": grpc.get("serviceName") or orig.get("serviceName", "")}
    if net == "httpupgrade":
        hu = stream.get("httpupgradeSettings", {})
        return {"type": "httpupgrade", "path": hu.get("path", "/"), "host": hu.get("host", "")}
    if net == "xhttp":
        xh = stream.get("xhttpSettings", {})
        return {"type": "xhttp", "path": xh.get("path", "/"), "host": xh.get("host", "")}
    if net == "http":
        http = stream.get("httpSettings", {})
        return {"type": "http", "host": http.get("host") or [], "path": http.get("path", "/")}
    if net == "quic":
        return {"type": "quic"}
    if net == "kcp":
        # sing-box 的 mKCP 走单独协议类型，不在 v2ray transport 体系内
        return {"type": "quic"}
    return None


def _singbox_tls(stream: Dict[str, Any], server: str) -> Dict[str, Any]:
    """sing-box 侧的 TLS。

    注意：`insecure` 是 sing-box 自己的字段（合法）；它是 Xray 的
    allowInsecure 已被 26.x 移除，两者不可混用 —— 内核配置由 parse 层
    单独生成，不走这里。
    """
    sec = stream.get("security")
    if sec == "reality":
        r = stream.get("realitySettings", {})
        pk = r.get("password") or r.get("publicKey", "")
        return {
            "enabled": True, "server_name": r.get("serverName", server), "insecure": True,
            "reality": {"enabled": True, "public_key": pk,
                        "short_id": r.get("shortId", "")},
            "utls": {"enabled": True, "fingerprint": r.get("fingerprint", "chrome")},
        }
    tls = stream.get("tlsSettings", {})
    return {
        "enabled": True,
        "server_name": tls.get("serverName", server),
        "insecure": True,
        **({"alpn": tls["alpn"]} if tls.get("alpn") else {}),
    }


def to_singbox_outbound(node_str: str, name: str) -> Optional[Dict[str, Any]]:
    """节点链接 -> sing-box outbound（tag = 节点名）"""
    outbound, server, port, proto = parse_node(node_str)
    if not outbound:
        return None
    stream = outbound.get("streamSettings", {}) or {}
    sec = stream.get("security")
    try:
        if proto in ("vless", "vmess"):
            user = outbound["settings"]["vnext"][0]["users"][0]
            o: Dict[str, Any] = {
                "type": proto, "tag": name, "server": server, "server_port": port,
                "uuid": user["id"],
            }
            if proto == "vmess":
                o["alter_id"] = user.get("alterId", 0)
                o["security"] = user.get("security", "auto")
            else:
                o["packet_encoding"] = "xudp"
                if user.get("flow"):
                    o["flow"] = user["flow"]
            if sec in ("tls", "reality"):
                o["tls"] = _singbox_tls(stream, server)
            transport = _singbox_transport(stream)
            if transport:
                o["transport"] = transport
            return o

        if proto == "trojan":
            srv = outbound["settings"]["servers"][0]
            o = {"type": "trojan", "tag": name, "server": server, "server_port": port,
                 "password": srv["password"], "tls": _singbox_tls(stream, server)}
            transport = _singbox_transport(stream)
            if transport:
                o["transport"] = transport
            return o

        if proto == "ss":
            srv = outbound["settings"]["servers"][0]
            return {"type": "shadowsocks", "tag": name, "server": server, "server_port": port,
                    "method": srv["method"], "password": srv["password"]}

        if proto == "hysteria2":
            srv = outbound["settings"]["servers"][0]
            tls = stream.get("tlsSettings", {})
            o = {
                "type": "hysteria2", "tag": name, "server": server, "server_port": port,
                "up_mbps": 100, "down_mbps": 100, "password": srv["password"],
                "tls": {"enabled": True, "server_name": tls.get("serverName", server),
                        "insecure": True,
                        "alpn": tls.get("alpn", ["h3"])},
            }
            obfs = outbound.get("_hy_obfs")
            if obfs:
                o["obfs"] = {"type": obfs["type"], "password": obfs["password"]}
            return o
    except Exception:
        return None
    return None


# ---------------------------------------------------------------- 兼容旧名
convert_to_clash_dict = to_clash_proxy
convert_to_singbox_outbound = to_singbox_outbound


def export_clash_yaml(clash_proxies: List[Dict[str, Any]], filepath: str) -> None:
    """导出 Clash 配置。

    零节点时不能写 `proxies: []` —— Clash/Mihomo 会以 "proxy list is empty"
    直接拒绝加载整个配置，此时给一个内置 DIRECT 兜底，保证配置始终可用。
    """
    proxies = list(clash_proxies)
    names = [p["name"] for p in proxies]
    if not names:
        proxies = [{"name": "DIRECT", "type": "direct"}]
        names = ["DIRECT"]
    config_dict = {
        "port": 7890, "socks-port": 7891, "allow-lan": True, "mode": "rule",
        "log-level": "info", "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXIES", "type": "select", "proxies": ["AUTO"] + names},
            {"name": "AUTO", "type": "url-test", "url": config.PROBE_TEST_URL,
             "interval": 300, "proxies": names},
        ],
        "rules": ["MATCH,PROXIES"],
    }
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.dump(config_dict, f, allow_unicode=True, sort_keys=False)


def export_singbox_json(sb_outbounds: List[Dict[str, Any]], filepath: str) -> None:
    """sb_outbounds 为已转换好的节点 outbound 列表（各自带 tag）

    必须包含 inbounds / route，且 selector / urltest 引用的 tag 全部真实存在，
    否则客户端加载即报错。
    """
    names = [o["tag"] for o in sb_outbounds if o.get("tag")]
    auto_targets = names or ["direct"]
    mixed_inbounds = [{
        "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080,
    }]
    outbounds: List[Dict[str, Any]] = [
        {"type": "selector", "tag": "select", "default": "auto",
         "outbounds": ["auto"] + auto_targets},
        {"type": "urltest", "tag": "auto", "outbounds": auto_targets,
         "url": config.PROBE_TEST_URL, "interval": "3m"},
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ]
    outbounds.extend(sb_outbounds)
    config_dict = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": mixed_inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"inbound": ["mixed-in"], "outbound": "select"},
            ],
            "final": "select",
            "auto_detect_interface": True,
        },
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(config_dict, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------- 命名与分组

def rename_node_link(raw_link: str, new_name: str) -> str:
    import base64
    try:
        if raw_link.startswith("vmess://"):
            b64 = raw_link[8:]
            b64 += "=" * (-len(b64) % 4)
            data = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
            data["ps"] = new_name
            new_b64 = base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode()
            return f"vmess://{new_b64}"
        return f"{raw_link.split('#')[0].strip()}#{new_name}"
    except Exception:
        return raw_link


def format_node_group(nodes_list: List[Dict[str, Any]], res_tag_force: bool = False
                      ) -> Tuple[List[str], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """按 `国旗 地区 序号 (家宽) - xiaohe` 规范命名，返回 (links, clash, singbox)"""
    links: List[str] = []
    proxies: List[Dict[str, Any]] = []
    singbox: List[Dict[str, Any]] = []

    for idx, item in enumerate(nodes_list, start=1):
        cc = item["country"]
        flag = config.get_country_flag(cc)
        c_name = config.COUNTRY_NAMES.get(cc, cc)
        tag = " (家宽)" if (item["is_residential"] or res_tag_force) else ""
        node_name = f"{flag} {c_name} {idx:02d}{tag} - xiaohe"

        proxies.append({**item["clash_proxy"], "name": node_name})
        sb = to_singbox_outbound(item["link"], node_name)
        if sb:
            singbox.append(sb)
        links.append(rename_node_link(item["link"], node_name))

    return links, proxies, singbox
