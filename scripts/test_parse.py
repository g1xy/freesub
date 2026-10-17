"""freesub 回归测试：解析 / 导出 / 测活调度 / 甄别 / 报告。

独立运行：  python scripts/test_parse.py
pytest：    pytest scripts/test_parse.py

第三方依赖（requests / yaml / maxminddb）用 stub 注入，纯逻辑验证不联网；
涉及 xray 二进制的路径用 mock 替代。
"""
from __future__ import annotations

import base64
import json
import os
import socket
import sys
import tempfile
from unittest.mock import MagicMock, patch

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
# 项目根目录（xray.exe 等二进制所在处）——测试会把 cwd 切到临时目录
_PROJECT_DIR = os.path.dirname(_SCRIPTS_DIR)
# 切到临时目录：避免 import 时的副作用污染工作区
_TMP = tempfile.mkdtemp(prefix="freesub_test_")
os.chdir(_TMP)
sys.path.insert(0, _SCRIPTS_DIR)

# 用 MagicMock 替换第三方依赖模块，纯逻辑验证不联网
for _name in ("requests", "requests.adapters", "urllib3", "urllib3.util",
              "urllib3.util.retry", "yaml", "maxminddb"):
    sys.modules.setdefault(_name, MagicMock())

import main  # noqa: E402
from freesub import config, logutil  # noqa: E402
from freesub.classifier import classify_and_filter  # noqa: E402
from freesub.exporters import format_node_group, to_clash_proxy, to_singbox_outbound  # noqa: E402
from freesub.fetcher import SourceHealth, dedup_nodes, extract_nodes_from_text  # noqa: E402
from freesub.logutil import record_drop, report_drop_stats, reset_drops, snapshot_drops  # noqa: E402
from freesub.parse import (  # noqa: E402
    clear_cache, is_kernel_probeable, parse_node, strip_private_keys,
)
from freesub.prober import _probe_with_isolation, build_batch_config, probe_batch, validate_config  # noqa: E402
from freesub.reporter import write_meta  # noqa: E402

UUID = "11111111-2222-3333-4444-555555555555"
TROJAN = "trojan://mypassword@1.2.3.4:443?sni=hello.com&type=ws&path=%2Fws#node"
VLESS = (f"vless://{UUID}@5.6.7.8:443?encryption=none&security=tls&sni=a.com"
         "&type=ws&path=%2Fws#node")
VLESS_GRPC = (f"vless://{UUID}@5.6.7.8:443?security=reality&pbk=PUBKEY&sid=ab"
              "&fp=chrome&type=grpc&serviceName=gsvc&mode=gun&authority=auth.com#grpc")
VLESS_HTTPUP = f"vless://{UUID}@5.6.7.8:8443?type=httpupgrade&path=%2Fup&host=h.com#hu"
VLESS_XHTTP = (f"vless://{UUID}@5.6.7.8:443?type=xhttp&path=%2Fxh&host=x.com"
               "&security=tls&sni=x.com#xh")
VMESS = "vmess://" + base64.b64encode(json.dumps({
    "v": "2", "add": "9.9.9.9", "port": "443", "id": UUID,
    "aid": "0", "net": "ws", "host": "b.com", "path": "/vm", "tls": "tls"
}).encode()).decode()
VMESS_QUIC = "vmess://" + base64.b64encode(json.dumps({
    "v": "2", "add": "9.9.9.9", "port": "443", "id": UUID, "aid": "0",
    "net": "quic", "type": "none", "host": "q.com", "path": "/q", "tls": "tls"
}).encode()).decode()
VMESS_GRPC = "vmess://" + base64.b64encode(json.dumps({
    "v": "2", "add": "9.9.9.9", "port": "443", "id": UUID, "aid": "0",
    "net": "grpc", "path": "svcname", "host": "g.com", "tls": ""
}).encode()).decode()
SS = "ss://" + base64.b64encode(b"aes-256-gcm:pass123").decode() + "@8.8.8.8:8388#node"
SS_BAD_CIPHER = "ss://" + base64.b64encode(b"bf-cfb:pw").decode() + "@8.8.8.8:8388#node"
SS_PLUGIN = ("ss://" + base64.b64encode(b"aes-256-gcm:pw").decode()
             + "@8.8.8.8:8388?plugin=obfs-local%3Bobfs%3Dhttp#node")
HY2 = ("hysteria2://authpass@7.7.7.7:443?sni=h2.com&obfs=salamander"
       "&obfs-password=opwd&insecure=1#node")


# ================================================================ P0 回归

def test_trojan_convert_not_dropped():
    """回归：trojan 分支曾因引用未定义的 stream 抛 NameError，被 except 吞掉后返回 None"""
    proxy = to_clash_proxy(TROJAN, "T1")
    assert proxy is not None, "trojan 节点被静默丢弃（stream 未定义）"
    assert proxy["type"] == "trojan"
    assert proxy["password"] == "mypassword"
    assert proxy["sni"] == "hello.com"


def test_singbox_outbounds_are_defined():
    """回归：singbox.json 曾只写 selector/urltest，引用的节点 tag 全部未定义"""
    nodes = [
        {"link": VLESS, "clash_proxy": to_clash_proxy(VLESS, "n1"), "country": "JP", "is_residential": False},
        {"link": TROJAN, "clash_proxy": to_clash_proxy(TROJAN, "n2"), "country": "HK", "is_residential": True},
        {"link": HY2, "clash_proxy": to_clash_proxy(HY2, "n3"), "country": "US", "is_residential": False},
    ]
    links, proxies, sb_outbounds = format_node_group(nodes)
    assert len(links) == 3 and len(proxies) == 3 and len(sb_outbounds) == 3

    path = os.path.join(_TMP, "singbox.json")
    main.export_singbox_json(sb_outbounds, path)
    cfg = json.load(open(path, encoding="utf-8"))
    defined = {o.get("tag") for o in cfg["outbounds"] if o.get("tag")}
    for group in cfg["outbounds"]:
        if group["type"] in ("selector", "urltest"):
            for tag in group["outbounds"]:
                assert tag in defined, f"组 '{group['tag']}' 引用了未定义的 outbound: {tag}"
    assert sum(1 for o in cfg["outbounds"] if o["type"] in
               ("vless", "vmess", "trojan", "shadowsocks", "hysteria2")) == 3
    # inbounds / route 必须存在，否则 sing-box 加载即失败
    assert cfg.get("inbounds"), "sing-box 配置缺少 inbounds"
    assert cfg.get("route"), "sing-box 配置缺少 route"


def test_hysteria2_probe_not_skipped():
    """回归：测活函数曾对 hysteria2 直接 return None，抓了却不测"""
    src = open(os.path.join(_SCRIPTS_DIR, "freesub", "prober.py"), encoding="utf-8").read()
    assert 'proto == "hysteria2"' not in src, "测活仍在跳过 hysteria2"


def test_hy2_obfs_not_leaked_to_xray_config():
    """_ 前缀暂存字段不得进入 Xray 内核配置（未知字段会导致内核启动失败）"""
    outbound, server, port, proto = parse_node(HY2)
    assert proto == "hysteria2" and outbound is not None
    assert outbound.get("_hy_obfs", {}).get("type") == "salamander"
    cleaned = strip_private_keys(outbound)
    assert "_hy_obfs" not in cleaned
    tls = cleaned["streamSettings"]["tlsSettings"]
    assert tls["serverName"] == "h2.com"
    assert tls["alpn"] == ["h3"]
    # allowInsecure 已被 Xray 26.x 移除，写进内核配置会导致整批启动失败
    assert "allowInsecure" not in tls


def test_readme_worker_url_is_plain():
    """回归：Worker 示例里的 raw URL 曾被写成 Markdown 链接语法"""
    src = open(os.path.join(_SCRIPTS_DIR, "freesub", "reporter.py"), encoding="utf-8").read()
    assert "[https://raw.githubusercontent.com/]" not in src
    assert '"https://raw.githubusercontent.com/"' in src
    # PAT 必须来自环境变量，不得明文硬编码
    assert 'env.GITHUB_PAT' in src


def test_dedup_by_link_core():
    """同一节点在不同源里备注不同，应归一化去重，避免重复测活"""
    a = "vless://uuid@1.1.1.1:443?x=1#备注A"
    b = "vless://uuid@1.1.1.1:443?x=1#备注B"
    c = "vless://uuid@2.2.2.2:443?x=1#备注C"
    assert len(dedup_nodes([a, b, c])) == 2


def test_parse_result_is_cached():
    """同一链接全链路只解析一次"""
    from freesub.parse import clear_cache, parse_node_to_xray_outbound
    clear_cache()
    assert parse_node_to_xray_outbound(TROJAN) is parse_node_to_xray_outbound(TROJAN)


# ================================================================ 传输层覆盖

def test_all_transports_produce_stream_settings():
    """内核（Xray 26.x）支持的传输层必须生成对应子结构

    P1 #19 补全了 grpc/httpupgrade/xhttp；26.x 又移除了 h2/quic/kcp，
    这类节点改为降级为 raw 并把原值暂存给 Clash/sing-box 导出。
    """
    cases = [
        (VLESS, "ws", "wsSettings"),
        (VLESS_GRPC, "grpc", "grpcSettings"),
        (VLESS_HTTPUP, "httpupgrade", "httpupgradeSettings"),
        (VLESS_XHTTP, "xhttp", "xhttpSettings"),
        (VMESS, "ws", "wsSettings"),
        (VMESS_GRPC, "grpc", "grpcSettings"),
    ]
    for link, expect_net, expect_key in cases:
        outbound, _, _, proto = parse_node(link)
        assert outbound is not None, f"{proto}/{expect_net} 解析失败"
        stream = outbound["streamSettings"]
        assert stream["network"] == expect_net, f"{link[:40]} network 应为 {expect_net}"
        assert expect_key in stream, f"{link[:40]} 缺少 {expect_key}（会导致内核启动失败）"


def test_removed_transports_downgraded_but_exported():
    """回归：26.x 移除的 h2/quic/kcp 传输

    内核侧必须降级为 raw（否则整批配置启动失败），但 Clash / sing-box
    仍要拿到原始传输层，否则这些节点在客户端会被配错。
    """
    for typ, expect_orig in (("h2", "http"), ("http", "http"), ("quic", "quic"), ("kcp", "kcp")):
        link = f"vless://{UUID}@1.1.1.1:443?type={typ}&path=%2Fp&host=h.com&security=tls&sni=x.com#n"
        outbound, _, _, _ = parse_node(link)
        assert outbound is not None, f"{typ} 应保留解析"
        stream = outbound["streamSettings"]
        assert stream["network"] == "raw", f"{typ} 内核侧应降级为 raw，实际 {stream['network']}"
        assert stream.get("_originalNetwork") == expect_orig, \
            f"{typ} 原传输层应暂存为 {expect_orig}，实际 {stream.get('_originalNetwork')}"
        # 内核配置不得含内核已移除的 xxxSettings
        blob = json.dumps(strip_private_keys(outbound))
        for gone in ("quicSettings", "kcpSettings", "httpSettings"):
            assert gone not in blob, f"{typ} 内核配置残留已移除的 {gone}"

        # 导出侧必须用原值
        clash = to_clash_proxy(link, "X")
        assert clash is not None, f"{typ} Clash 导出被误伤"
        assert clash.get("network") == expect_orig, \
            f"{typ} Clash network 应为 {expect_orig}，实际 {clash.get('network')}"


def test_grpc_settings_content():
    outbound, _, _, _ = parse_node(VLESS_GRPC)
    grpc = outbound["streamSettings"]["grpcSettings"]
    assert grpc["serviceName"] == "gsvc", "serviceName 解析错误"
    assert grpc["multiMode"] is True, "mode=gun 应映射为 multiMode"
    assert grpc["authority"] == "auth.com"
    # Reality 必须完整，否则握手必失败
    reality = outbound["streamSettings"]["realitySettings"]
    assert reality["password"] == "PUBKEY"
    # 该链接未带 sni，回落到服务器地址
    assert reality["serverName"] == "5.6.7.8"
    assert reality["shortId"] == "ab"


def test_reality_requires_public_key():
    """缺少 pbk 的 reality 节点无法工作，应在解析阶段就丢弃而非白跑测活"""
    link = f"vless://{UUID}@1.1.1.1:443?security=reality&sni=a.com&type=tcp#x"
    reset_drops()
    clear_cache()
    outbound, _, _, _ = parse_node(link)
    assert outbound is None
    assert "vless_missing_reality_pbk" in snapshot_drops()


def test_removed_kcp_transport_is_downgraded():
    """kcp 在 26.x 已移除：内核侧降级为 raw，原值保留给客户端导出"""
    link = f"vless://{UUID}@1.1.1.1:443?type=kcp&headerType=srtp&seed=abc#k"
    outbound, _, _, _ = parse_node(link)
    stream = outbound["streamSettings"]
    assert stream["network"] == "raw", "内核侧应降级为 raw"
    assert "kcpSettings" not in stream, "不得写入内核已移除的 kcpSettings"
    assert stream["_originalNetwork"] == "kcp", "原传输层应暂存供导出"
    clash = to_clash_proxy(link, "X")
    assert clash["network"] == "kcp", "Clash 仍应保留 kcp"
    assert clash["kcp-opts"]["header"]["type"] == "srtp"


def test_tcp_http_header_request():
    link = f"vless://{UUID}@1.1.1.1:443?type=tcp&headerType=http&host=a.com&path=%2Fp#t"
    outbound, _, _, _ = parse_node(link)
    raw = outbound["streamSettings"]["rawSettings"]
    assert raw["header"]["type"] == "http"
    request = raw["header"]["request"]
    assert request["headers"]["Host"] == ["a.com"]
    assert request["path"] == ["/p"]
    # Clash 侧必须能还原出等价的 http-opts，否则客户端连不上
    proxy = to_clash_proxy(link, "X")
    assert proxy["network"] == "tcp"
    method, path, headers = proxy["http-opts"]
    assert method == "GET" and path == "/p" and headers["Host"] == ["a.com"]


def test_transports_mapped_to_all_three_clients():
    """新增传输层必须在 Clash 与 sing-box 侧都有等价映射，否则导出的节点是坏的"""
    expectations = {
        VLESS_GRPC: ("grpc", "grpc-opts", "grpc"),
        VLESS_HTTPUP: ("httpupgrade", "httpupgrade-opts", "httpupgrade"),
        VLESS_XHTTP: ("xhttp", "xhttp-opts", "xhttp"),
        VMESS_QUIC: ("quic", "quic-opts", "quic"),
    }
    for link, (clash_net, clash_key, sb_type) in expectations.items():
        proxy = to_clash_proxy(link, "X")
        sb = to_singbox_outbound(link, "X")
        assert proxy is not None and sb is not None, f"{clash_net} 三端转换缺失"
        assert proxy.get("network") == clash_net, f"{clash_net} 的 Clash network 映射缺失"
        assert clash_key in proxy, f"{clash_net} 缺少 {clash_key}"
        assert sb["transport"]["type"] == sb_type, f"{clash_net} 的 sing-box transport 映射缺失"


def test_invalid_uuid_rejected_at_parse_time():
    """回归：UUID 格式非法的脏数据必须提前丢弃

    公开源实测存在 `vless://aacbbac-cbaa-cbaa-...@127.0.0.1:8080` 这类节点：
    UUID 首段不足 8 位，内核解析配置时报 `encoding/hex: invalid ...`，
    会让**整批**节点启动失败。必须在解析阶段拦下。
    """
    bad_uuid = "aacbbac-cbaa-cbaa-dcab-bcbcacaabacb"
    vless_link = f"vless://{bad_uuid}@1.2.3.4:443?security=tls&type=tcp#x"
    vmess_payload = base64.b64encode(json.dumps({
        "v": "2", "add": "1.2.3.4", "port": "443", "id": bad_uuid,
        "aid": "0", "net": "tcp"}).encode()).decode()
    for link in (vless_link, f"vmess://{vmess_payload}#y"):
        reset_drops()
        clear_cache()
        assert parse_node(link)[0] is None, "非法 UUID 必须丢弃"
        assert any("invalid_uuid" in k for k in snapshot_drops()), snapshot_drops()


def test_vmess_malformed_base64_rejected_cleanly():
    """vmess 的 base64 / JSON 异常应归类丢弃，而不是抛到通用异常分支"""
    reset_drops()
    clear_cache()
    assert parse_node("vmess://!!!!not-base64!!!!#x")[0] is None
    stats = snapshot_drops()
    assert any(k.startswith(("vmess_bad_base64", "vmess_bad_json_shape",
                             "parse_exception")) for k in stats), stats

    # 折行的长 base64（部分源会折行）应能正确解析
    reset_drops()
    clear_cache()
    payload = base64.b64encode(json.dumps({
        "v": "2", "add": "9.9.9.9", "port": "443", "id": UUID,
        "aid": "0", "net": "tcp"}).encode()).decode()
    wrapped = payload[:20] + "\n" + payload[20:]
    assert parse_node(f"vmess://{wrapped}#z")[0] is not None, "折行 base64 应可解析"


def test_bogus_hosts_rejected_at_parse_time():
    """回归：回环 / 私网 / 占位地址既连不通，也可能引发内核解析错误

    实测源里有 `vless://...@127.0.0.1:8080` 这类节点。它们若进批次配置，
    既浪费测活预算，又可能拖垮整批。
    """
    # 只拦确定性无效的；私网段刻意不拦（部分机场用内网中转出口，需交给内核判断）
    bogus = ["127.0.0.1", "localhost", "0.0.0.0", "example.com", "your.domain.com"]
    for host in bogus:
        link = f"vless://{UUID}@{host}:443?security=tls&type=tcp#x"
        reset_drops()
        clear_cache()
        assert parse_node(link)[0] is None, f"{host} 应被丢弃"

    for prefix in ("trojan://pw@", "ss://", "hysteria2://pw@"):
        if prefix.startswith("ss://"):
            link = prefix + base64.b64encode(b"aes-256-gcm:pw").decode() + "@127.0.0.1:8388#x"
        else:
            link = prefix + "127.0.0.1:443" + ("?sni=x.com" if "hysteria" in prefix else "?sni=x.com")
        clear_cache()
        assert parse_node(link)[0] is None, f"{prefix} 的回环地址应被丢弃"

    # 合法地址必须保留（含私网段，交给内核实测）
    for host in ("1.2.3.4", "8.8.8.8", "10.0.0.1", "192.168.1.1"):
        clear_cache()
        link = f"vless://{UUID}@{host}:443?security=tls&type=tcp#x"
        assert parse_node(link)[0] is not None, f"{host} 是合法地址，不该被丢"


def test_flow_requires_tls_or_reality():
    """回归：Xray 26.x 校验 flow 与加密方式的匹配

    security=none 时带 flow 会报
    `VLESS users: "flow" doesn't support "none" in this version`，
    进而让整批配置启动失败 —— 单个畸形节点会带走同批所有好节点。
    """
    # 裸 TCP（security=none）带 flow 必须被剥掉
    bare = f"vless://{UUID}@1.1.1.1:443?security=none&flow=xtls-rprx-vision&type=tcp#x"
    outbound, _, _, _ = parse_node(bare)
    assert outbound is not None
    user = outbound["settings"]["vnext"][0]["users"][0]
    assert "flow" not in user, "security=none 时不得保留 flow，否则内核启动失败"

    # REALITY + flow 必须保留
    pk = base64.urlsafe_b64encode(b"x" * 32).decode().rstrip("=")
    reality = f"vless://{UUID}@1.1.1.1:443?security=reality&pbk={pk}&flow=xtls-rprx-vision&type=tcp#r"
    outbound2, _, _, _ = parse_node(reality)
    user2 = outbound2["settings"]["vnext"][0]["users"][0]
    assert user2["flow"] == "xtls-rprx-vision", "REALITY + flow 必须保留"
    assert to_clash_proxy(reality, "X")["flow"] == "xtls-rprx-vision"
    assert to_singbox_outbound(reality, "X")["flow"] == "xtls-rprx-vision"


def test_flow_none_literal_is_dropped():
    """回归：源里存在 `flow=none` 的显式写法（实测真实链接命中）

    内核不接受 flow=none 本身，会报
    `VLESS users: "flow" doesn't support "none" in this version`。
    """
    link = (f"vless://f959a3fc-2e55-4bde-8ed4-4fab249f8733@172.67.172.155:2083"
            f"?security=tls&flow=none&sni=a.com&type=ws&path=%2Fh#n")
    outbound, _, _, _ = parse_node(link)
    assert outbound is not None
    user = outbound["settings"]["vnext"][0]["users"][0]
    assert "flow" not in user, "flow=none 必须剔除，否则内核启动失败"
    assert "flow" not in to_clash_proxy(link, "X")
    assert "flow" not in to_singbox_outbound(link, "X")


def test_vless_flow_preserved():
    """xtls-rprx-vision flow 丢失会导致 Reality 节点握手失败"""
    link = f"vless://{UUID}@1.1.1.1:443?security=reality&pbk=K&flow=xtls-rprx-vision&type=tcp#f"
    outbound, _, _, _ = parse_node(link)
    assert outbound["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision"
    assert to_clash_proxy(link, "X")["flow"] == "xtls-rprx-vision"
    assert to_singbox_outbound(link, "X")["flow"] == "xtls-rprx-vision"


# ================================================================ ss 处理

def test_ss_cipher_whitelist_filters_unsupported():
    """P2 #18：VALID_SS_CIPHERS 曾定义却从未使用，内核不支持的 cipher 会白跑测活"""
    from freesub.parse import clear_cache

    # 三个明确不在内核支持列表内的 cipher
    for bad_cipher in (b"bf-cfb:pw", b"chacha20-ietf:pw", b"camellia-128-cfb:pw"):
        reset_drops()
        clear_cache()  # 否则命中解析缓存，丢弃原因不会重新计数
        link = "ss://" + base64.b64encode(bad_cipher).decode() + "@8.8.8.8:8388#node"
        bad, _, _, _ = parse_node(link)
        assert bad is None, f"{bad_cipher} 不在内核支持列表，应提前丢弃"
        stats = snapshot_drops()
        assert any(k.startswith("ss_unsupported_cipher") for k in stats), stats

    reset_drops()
    clear_cache()
    good, _, _, _ = parse_node(SS)
    assert good is not None, "aes-256-gcm 属白名单内，不该被丢"
    assert not any(k.startswith("ss_unsupported_cipher") for k in snapshot_drops())


def test_ss_plugin_dropped_before_probe():
    """ss + obfs/v2ray-plugin 内核不支持，真实测活不可能通过，应在候选阶段就丢"""
    reset_drops()
    outbound, _, _, _ = parse_node(SS_PLUGIN)
    assert outbound is None, "带 plugin 的 ss 节点必须提前丢弃，否则白耗测活预算"
    stats = snapshot_drops()
    assert any(k.startswith("ss_plugin_unsupported:obfs-local") for k in stats), stats


# ================================================================ 测活调度

def test_batch_config_pairs_inbound_with_outbound():
    """批量测活配置：inbound / outbound / routing 必须一一对应，且不含 _ 前缀字段"""
    items = [
        (VLESS, "5.6.7.8", 443, "vless"),
        (TROJAN, "1.2.3.4", 443, "trojan"),
        ("not-a-node", "", 0, "unknown"),
    ]
    cfg, pairs = build_batch_config(items, [20001, 20002, 20003])
    assert len(pairs) == 2, "无法解析的节点不得占用 inbound"
    assert len(cfg["inbounds"]) == 2
    assert len(cfg["routing"]["rules"]) == 2
    assert len(cfg["outbounds"]) == 3, "节点 outbound + 兜底 direct"

    out_tags = {o["tag"] for o in cfg["outbounds"]}
    for rule, inbound in zip(cfg["routing"]["rules"], cfg["inbounds"]):
        assert rule["inboundTag"] == [inbound["tag"]]
        assert rule["outboundTag"] in out_tags

    # _ 前缀暂存字段绝不能进内核配置（以 vmess 为例，其 obfs 场景由 hy2 覆盖测试）
    vmess_ws = VMESS
    cfg2, pairs2 = build_batch_config([(vmess_ws, "9.9.9.9", 443, "vmess")], [20010])
    assert len(pairs2) == 1
    assert not any(k.startswith("_") for k in cfg2["outbounds"][0])


def test_batch_probe_reuses_single_process():
    """核心收益验证：N 个节点只启动 ceil(N/batch) 个内核进程，而非 N 个"""
    items = [(f"vless://11111111-2222-3333-4444-555555555555@10.0.0.{i}:443?security=none#n", f"10.0.0.{i}", 443, "vless")
             for i in range(1, 26)]
    started = []

    class FakeProc:
        def __init__(self, *args, **kwargs):
            started.append(args)

        def terminate(self): pass

        def kill(self): pass

        def wait(self, timeout=None): return 0

    def fake_probe(item, port):
        return (item[0], item[1], item[2], item[3], "1.2.3.4", 100, True)

    with patch.object(config, "PROBE_BATCH_SIZE", 10), \
         patch("freesub.prober.subprocess.Popen", FakeProc), \
         patch("freesub.prober.wait_ports_ready", lambda ports, deadline_sec=20.0, require_all=True: True), \
         patch("freesub.prober.probe_via_socks", fake_probe), \
         patch("freesub.prober.validate_config", lambda cfg, path: True), \
         patch("freesub.prober.kill_proc", lambda p: None), \
         patch("freesub.prober.xray_version", lambda: "fake"):
        alive = main.run_real_delay_test_xray(items)

    assert len(alive) == 25, f"应全部存活，实际 {len(alive)}"
    assert len(started) == 3, f"25 节点 / 每批 10 应只启动 3 个内核进程，实际 {len(started)}"


def test_batch_failure_falls_back_to_single():
    """批量内核启动失败时必须回退单节点模式，不能整批丢节点"""
    items = [("vless://11111111-2222-3333-4444-555555555555@10.0.0.1:443?security=none#a", "10.0.0.1", 443, "vless"),
             ("vless://11111111-2222-3333-4444-555555555555@10.0.0.2:443?security=none#b", "10.0.0.2", 443, "vless")]
    single_calls = []

    def fake_single(item):
        single_calls.append(item)
        return (item[0], item[1], item[2], item[3], "1.2.3.4", 100, True)

    with patch("freesub.prober.probe_batch", lambda batch: None), \
         patch("freesub.prober.probe_single_node", fake_single):
        alive = main.run_real_delay_test_xray(items)

    assert len(alive) == 2
    assert len(single_calls) == 2, "回退路径应为每个节点各测一次"


def test_invalid_batch_config_isolates_bad_node():
    """P0 防御：单个畸形节点不得拖垮整批

    整批配置若过不了 xray -test，应二分隔离出坏节点，好节点照常测活。
    """
    items = [(f"vless://11111111-2222-3333-4444-555555555555@10.0.0.{i}:443?security=none#n", f"10.0.0.{i}", 443, "vless")
             for i in range(1, 9)]
    bad_host = "10.0.0.4"
    probed = []

    def fake_validate(cfg, path):
        # 只要批次里包含被标记为坏的节点，就判定整批非法
        return bad_host not in cfg["outbounds"][0]["settings"]["vnext"][0]["address"] \
            if False else all(o["settings"]["vnext"][0]["address"] != bad_host
                              for o in cfg["outbounds"] if o["protocol"] == "vless")

    def fake_probe(item, port):
        probed.append(item[1])
        return (item[0], item[1], item[2], item[3], "1.2.3.4", 100, True)

    reset_drops()
    with patch("freesub.prober.validate_config", fake_validate), \
         patch("freesub.prober.probe_via_socks", fake_probe), \
         patch("freesub.prober.subprocess.Popen", lambda *a, **k: MagicMock(wait=lambda t=None: 0)), \
         patch("freesub.prober.wait_ports_ready", lambda ports, deadline_sec=20.0, require_all=True: True), \
         patch("freesub.prober.kill_proc", lambda p: None):
        result = probe_batch(items)

    assert result is not None, "配置非法应走隔离路径，不该返回 None（那是内核不可用）"
    assert bad_host not in probed, "坏节点必须被隔离，不得测活"
    assert len(probed) == 7, f"其余 7 个好节点应全部保留，实际 {len(probed)}"
    assert snapshot_drops().get("batch_isolated_bad_node") == 1


def test_slow_port_start_splits_batch_instead_of_dropping():
    """回归：大批量 inbound 起不来时不得整批丢弃

    内核对同时监听端口数有上限，超出会静默部分失败。旧实现一旦在启动窗口内
    没等到全部端口就返回空列表 —— 实测 40 个一批有 37 个被白丢。
    现在应延长等待，仍失败则拆小批重试，最差逐节点兜底。
    """
    from freesub.prober import _probe_in_smaller_batches

    items = [(f"vless://11111111-2222-3333-4444-555555555555@10.0.1.{i}:443?security=none#n", f"10.0.1.{i}", 443, "vless")
             for i in range(1, 9)]

    probed = []

    def fake_single(item):
        probed.append(item[1])
        return (item[0], item[1], item[2], item[3], "1.2.3.4", 100, True)

    def fake_probe(item, port):
        probed.append(item[1])
        return (item[0], item[1], item[2], item[3], "1.2.3.4", 100, True)

    def always_not_ready(ports, deadline_sec=20.0, require_all=True):
        return False

    # 端口始终起不来：拆批最终应落到逐节点兜底，8 个节点一个都不能少
    reset_drops()
    with patch("freesub.prober.wait_ports_ready", always_not_ready), \
         patch("freesub.prober.probe_via_socks", fake_probe), \
         patch("freesub.prober.probe_single_node", fake_single), \
         patch("freesub.prober.validate_config", lambda cfg, path: True), \
         patch("freesub.prober.kill_proc", lambda p: None), \
         patch("freesub.prober.subprocess.Popen",
               lambda *a, **k: MagicMock(wait=lambda t=None: 0)):
        result = _probe_in_smaller_batches(items)

    assert len(result) == 8, f"端口起不来也必须保住全部节点，实际 {len(result)}"
    assert sorted(set(probed)) == sorted(f"10.0.1.{i}" for i in range(1, 9))
    assert snapshot_drops().get("batch_ports_not_ready", 0) > 0, "应记录端口未就绪"


def test_small_batch_port_ready_keeps_batch_mode():
    """端口正常就绪时仍走批量路径，不因拆批逻辑退化"""
    from freesub.prober import probe_batch as _pb

    items = [(f"vless://11111111-2222-3333-4444-555555555555@10.0.3.{i}:443?security=none#n", f"10.0.3.{i}", 443, "vless")
             for i in range(1, 5)]
    probed = []

    def fake_probe(item, port):
        probed.append(item[1])
        return (item[0], item[1], item[2], item[3], "1.2.3.4", 100, True)

    with patch("freesub.prober.wait_ports_ready",
               lambda ports, deadline_sec=20.0, require_all=True: True), \
         patch("freesub.prober.probe_via_socks", fake_probe), \
         patch("freesub.prober.validate_config", lambda cfg, path: True), \
         patch("freesub.prober.kill_proc", lambda p: None), \
         patch("freesub.prober.subprocess.Popen",
               lambda *a, **k: MagicMock(wait=lambda t=None: 0)):
        result = _pb(items)

    assert len(result) == 4
    assert "batch_ports_slow_start" not in snapshot_drops()


def test_tiny_batch_falls_back_to_serial():
    """拆到最小批次仍起不来时，逐节点兜底而非放弃"""
    from freesub.prober import _probe_in_smaller_batches

    items = [(f"vless://11111111-2222-3333-4444-555555555555@10.0.2.{i}:443?security=none#n", f"10.0.2.{i}", 443, "vless")
             for i in range(1, 3)]
    calls = []

    def fake_single(item):
        calls.append(item[1])
        return (item[0], item[1], item[2], item[3], "1.2.3.4", 100, True)

    with patch.object(config, "MIN_BATCH_SIZE", 8), \
         patch("freesub.prober.probe_single_node", fake_single):
        result = _probe_in_smaller_batches(items)

    assert len(result) == 2
    assert sorted(calls) == ["10.0.2.1", "10.0.2.2"], "最小批次应逐节点兜底"


def test_port_ready_partial_tolerance():
    """require_all=False 时多数端口就绪即可继续，榨干已启动的节点"""
    from freesub.prober import wait_ports_ready

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    port = listener.getsockname()[1]
    dead = allocate_ports_one()
    try:
        assert wait_ports_ready([port, dead], deadline_sec=0.5, require_all=True) is False
        assert wait_ports_ready([port, dead], deadline_sec=0.5, require_all=False) is True
    finally:
        listener.close()


def allocate_ports_one() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_validate_config_keeps_file_for_launch():
    """回归：validate_config 不得删除配置

    调用方（probe_batch / probe_single_node）在校验通过后要用**同一份文件**
    启动内核。若 validate_config 把文件删了，内核会因配置文件不存在而启动失败，
    表现为端口永不就绪 -> 无限拆批重试（实测 25->12->6 递归，耗时暴涨）。
    清理由调用方的 finally 块负责。
    """
    cfg = {"outbounds": [{"tag": "direct", "protocol": "freedom"}]}
    path = os.path.join(_TMP, "keep_check.json")
    with patch("freesub.prober.subprocess.run", return_value=MagicMock(returncode=0)):
        assert validate_config(cfg, path) is True
    assert os.path.exists(path), "校验后配置文件必须保留给 run 阶段使用"

    with patch("freesub.prober.subprocess.run", return_value=MagicMock(returncode=1)):
        assert validate_config(cfg, path) is False
    assert os.path.exists(path), "校验失败同样保留文件（由调用方清理）"


def test_singbox_validate_keeps_file_for_launch():
    """sing-box 侧同样问题：校验后必须保留配置给 run 阶段"""
    from freesub import sbprober

    cfg = {"log": {"level": "warn"},
           "inbounds": [{"type": "mixed", "tag": "i", "listen": "127.0.0.1", "listen_port": 20778}],
           "outbounds": [{"type": "hysteria2", "tag": "n", "server": "1.1.1.1",
                          "server_port": 443, "password": "p"}]}
    path = os.path.join(_TMP, "sb_keep.json")
    with patch("freesub.sbprober.subprocess.run", return_value=MagicMock(returncode=0)):
        assert sbprober.validate_config(cfg, path) is True
    assert os.path.exists(path), "sing-box 校验后必须保留配置文件"


def test_probe_batch_launches_with_the_validated_file():
    """probe_batch 校验后启动内核用的必须是同一份文件路径"""
    items = [(VLESS, "5.6.7.8", 443, "vless")]
    validated = []
    launched = []

    class FakeProc:
        def __init__(self, *a, **k):
            launched.append(a[0][-1])

        def terminate(self): pass

        def kill(self): pass

        def wait(self, timeout=None): return 0

    def fake_validate(cfg, path):
        validated.append(path)
        return True

    def fake_probe(item, port):
        return (item[0], item[1], item[2], item[3], "1.2.3.4", 100, True)

    with patch("freesub.prober.validate_config", fake_validate), \
         patch("freesub.prober.subprocess.Popen", FakeProc), \
         patch("freesub.prober.wait_ports_ready",
               lambda ports, deadline_sec=20.0, require_all=True: True), \
         patch("freesub.prober.probe_via_socks", fake_probe), \
         patch("freesub.prober.kill_proc", lambda p: None):
        alive = probe_batch(items)

    assert len(alive) == 1, "应成功测活"
    assert len(validated) == 1 and len(launched) == 1
    assert validated[0] == launched[0], (
        f"启动内核用的配置必须与校验时同一份：validate={validated[0]} launch={launched[0]}")


def test_repo_has_no_leftover_temp_configs():
    """仓库工作区不应残留任何临时配置

    临时配置一律写在系统临时目录（tempfile.mkstemp），工作区保持干净。
    """
    import glob
    project = _PROJECT_DIR
    patterns = ("xray_*.json", "sb_*.json", "v*.json", "t.json", "dbg.json",
                "xray.zip")
    leftovers = []
    for pat in patterns:
        leftovers.extend(glob.glob(os.path.join(project, pat)))
    assert not leftovers, f"工作区残留临时文件: {[os.path.basename(p) for p in leftovers]}"


def test_temp_config_lives_outside_workspace():
    """临时配置必须落在系统临时目录，而不是仓库工作区

    写在工作区会污染 git 状态，且异常路径下每轮会残留几百个文件
    （实测一轮跑出 99 个 sb_tmp_*.json）。
    """
    from freesub.prober import temp_config_path

    path = temp_config_path("xray_batch")
    try:
        assert not os.path.abspath(path).startswith(
            os.path.abspath(_PROJECT_DIR) + os.sep), \
            f"临时配置落在工作区内: {path}"
        assert os.path.exists(path), "应先创建空文件"
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def test_validate_config_writes_and_checks():
    """validate_config 必须以 xray -test 的退出码判定合法性"""
    cfg = {"outbounds": [{"tag": "direct", "protocol": "freedom"}]}
    path = os.path.join(_TMP, "v.json")
    with patch("freesub.prober.subprocess.run") as run:
        run.return_value = MagicMock(returncode=0)
        assert validate_config(cfg, path) is True
        args = run.call_args[0][0]
        assert "-test" in args, "必须使用 xray -test 做静态校验"
        assert args[1] == "run", "应使用 `xray run -test` 子命令"

        run.return_value = MagicMock(returncode=1)
        assert validate_config(cfg, path) is False


def test_missing_binary_skips_validation():
    """内核不可用时校验应放行，交由端口轮询兜底，避免误判整批非法"""
    cfg = {"outbounds": [{"tag": "direct", "protocol": "freedom"}]}
    with patch("freesub.prober.subprocess.run", side_effect=FileNotFoundError):
        assert validate_config(cfg, os.path.join(_TMP, "v.json")) is True


def test_probe_uses_median_delay():
    """PROBE_REPEAT > 1 时取中位数，避免单次抖动误杀优质节点

    注入的 time.time 序列为 [起, 止] × 3 → 三次耗时 300/90/120ms，中位数 120。
    """
    from freesub.prober import probe_via_socks

    reset_drops()

    class FakeResp:
        status_code = 204

    clock = [0.00, 0.30,   # 第 1 次：300ms
             0.30, 0.39,   # 第 2 次： 90ms
             0.39, 0.51]   # 第 3 次：120ms

    with patch.object(config, "PROBE_REPEAT", 3), \
         patch.object(config, "PROBE_TIMEOUT", 6.5), \
         patch.object(config, "MIN_DELAY_MS", 10), \
         patch.object(config, "MAX_DELAY_MS", 6300), \
         patch("freesub.prober.requests.get", return_value=FakeResp()), \
         patch("freesub.prober.time.time", side_effect=clock):
        res = probe_via_socks((TROJAN, "1.2.3.4", 443, "trojan"), 20001)

    assert res is not None, "三次探测均成功时不应判死"
    assert res[5] == 120, f"延迟应取中位数 120ms，实际 {res[5]}"


def test_probe_rejects_outlier_delays():
    """延迟超出 [MIN,MAX] 区间的节点判定不可用"""
    from freesub.prober import probe_via_socks

    class FakeResp:
        status_code = 204

    with patch.object(config, "PROBE_REPEAT", 1), \
         patch("freesub.prober.requests.get", return_value=FakeResp()), \
         patch("freesub.prober.time.time", side_effect=[0.0, 9.9]):
        assert probe_via_socks((TROJAN, "1.2.3.4", 443, "trojan"), 20001) is None


def test_extract_nodes_from_base64_text():
    payload = base64.b64encode((TROJAN + "\n" + VLESS).encode()).decode()
    assert len(extract_nodes_from_text(payload)) == 2
    assert extract_nodes_from_text("") == set()


# ================================================================ 甄别与报告

def test_duplicate_residential_ip_downgraded():
    """同一个物理出口 IP 在家宽池只能出现一次，杜绝一个 IP 刷出多条"家宽" """
    alive = [
        ("vless://11111111-2222-3333-4444-555555555555@h1.example.org:443?security=none#1", "h1", 443, "vless", "9.9.9.9", 100, True),
        ("vless://11111111-2222-3333-4444-555555555555@h2.example.org:443?security=none#2", "h2", 443, "vless", "9.9.9.9", 110, True),
        ("vless://11111111-2222-3333-4444-555555555555@h3.example.org:443?security=none#3", "h3", 443, "vless", "8.8.8.8", 120, True),
    ]
    fake_asn = MagicMock()
    fake_asn.get.side_effect = lambda ip: {
        "autonomous_system_number": 3462 if ip == "9.9.9.9" else 4780,
        "autonomous_system_organization": "CHT Taiwan Fixed Network" if ip == "9.9.9.9"
        else "Comcast Cable",
    }
    fake_country = MagicMock()
    fake_country.get.side_effect = lambda ip: {"country": {"iso_code": "TW" if ip == "9.9.9.9" else "US"}}

    with patch("freesub.classifier._get_readers", return_value=(fake_country, fake_asn)), \
         patch("freesub.classifier._close_all_readers"):
        result = classify_and_filter(alive)

    assert len(result) == 3
    res = [n for n in result if n["is_residential"]]
    assert len(res) == 2, f"重复出口 IP 应被降级，实际家宽数 {len(res)}"
    ips = [n["exit_ip"] for n in res]
    assert len(ips) == len(set(ips)), "家宽池出现重复出口 IP"


def test_cloudflare_anycast_never_residential():
    alive = [("vless://11111111-2222-3333-4444-555555555555@node.example.org:443?security=none#1", "h", 443, "vless", "104.16.1.1", 80, True)]
    fake_asn = MagicMock()
    fake_asn.get.return_value = {"autonomous_system_number": 13335,
                                  "autonomous_system_organization": "CLOUDFLARENET"}
    fake_country = MagicMock()
    fake_country.get.return_value = {"country": {"iso_code": "US"}}

    with patch("freesub.classifier._get_readers", return_value=(fake_country, fake_asn)), \
         patch("freesub.classifier._close_all_readers"):
        result = classify_and_filter(alive)

    assert result[0]["is_residential"] is False, "Cloudflare 任播 IP 绝不能进家宽池"


def test_unconfirmed_exit_never_residential():
    """未拿到穿透落地 IP 的节点绝不打家宽标签"""
    alive = [("vless://11111111-2222-3333-4444-555555555555@node.example.org:443?security=none#1", "h", 443, "vless", "1.1.1.1", 80, False)]
    fake_asn = MagicMock()
    fake_asn.get.return_value = {"autonomous_system_number": 3462,
                                  "autonomous_system_organization": "Data Communication Business Group"}
    fake_country = MagicMock()
    fake_country.get.return_value = {"country": {"iso_code": "TW"}}

    with patch("freesub.classifier._get_readers", return_value=(fake_country, fake_asn)), \
         patch("freesub.classifier._close_all_readers"):
        result = classify_and_filter(alive)

    assert result[0]["is_residential"] is False


def test_meta_json_contains_diagnostics():
    """P2 #20：meta.json 应能回答「这批节点的协议/国家/延迟/丢弃原因分布」"""
    reset_drops()
    record_drop("probe_failed:Timeout", 5)
    nodes = [
        {"link": VLESS, "clash_proxy": to_clash_proxy(VLESS, "a"), "country": "JP",
         "is_residential": False, "delay": 120, "proto": "vless"},
        {"link": TROJAN, "clash_proxy": to_clash_proxy(TROJAN, "b"), "country": "HK",
         "is_residential": True, "delay": 300, "proto": "trojan"},
    ]
    meta = write_meta(nodes, {"probe_sec": 12.3}, {})
    assert meta["counts"]["alive"] == 2
    assert meta["counts"]["residential"] == 1
    assert meta["protocols"] == {"vless": 1, "trojan": 1}
    assert meta["countries"]["JP"] == 1
    assert meta["delay_ms"]["p50"] > 0
    assert meta["drop_reasons"]["probe_failed:Timeout"] == 5
    assert os.path.exists(config.META_FILE)
    on_disk = json.load(open(config.META_FILE, encoding="utf-8"))
    assert on_disk["stages"]["probe_sec"] == 12.3


def test_source_health_persists_and_degrades():
    """P2 #17：源健康度需跨轮持久化，连续失败多的源本轮排到最后"""
    path = os.path.join(_TMP, "sources_status.json")
    h1 = SourceHealth(path)
    for _ in range(3):
        h1.record_failure("https://bad.example/sub", "HTTP 503")
    h1.record_success("https://good.example/sub", 42)
    h1.save()

    h2 = SourceHealth(path)
    assert h2.data["https://bad.example/sub"]["consecutive_failures"] == 3
    assert h2.data["https://good.example/sub"]["last_node_count"] == 42

    ordered = h2.order_sources(["https://bad.example/sub", "https://good.example/sub"], 3)
    assert ordered[0] == "https://good.example/sub", "健康源必须优先抓取"
    assert ordered[-1] == "https://bad.example/sub"

    # 全部源都被判降级时仍需保留抓取，避免空转导致空订阅
    assert len(h2.order_sources(["https://bad.example/sub"], 3)) == 1


def test_source_health_success_resets_streak():
    path = os.path.join(_TMP, "sources_status2.json")
    h = SourceHealth(path)
    h.record_failure("u", "err")
    h.record_failure("u", "err")
    h.record_success("u", 7)
    assert h.data["u"]["consecutive_failures"] == 0
    assert h.data["u"]["total_failure"] == 2


def test_drop_stats_reported():
    reset_drops()
    record_drop("x", 2)
    record_drop("y", 1)
    stats = report_drop_stats()
    assert stats["x"] == 2 and stats["y"] == 1
    assert logutil.total_dropped() == 3


# ================================================================ CLI / 平台

def test_cli_overrides_config():
    """CLI 参数必须真正写回 config（各模块通过 config.xxx 取值）"""
    args = main.build_arg_parser().parse_args(
        ["--max-candidates", "123", "--workers", "7", "--batch-size", "11",
         "--timeout", "2.5", "--budget", "60", "--repeat", "3"])
    main.apply_overrides(args)
    assert config.MAX_CANDIDATES == 123
    assert config.PROBE_WORKERS == 7
    assert config.PROBE_BATCH_SIZE == 11
    assert config.PROBE_TIMEOUT == 2.5
    assert config.TOTAL_BUDGET_SEC == 60
    assert config.PROBE_REPEAT == 3
    # 复位，避免影响后续用例
    main.apply_overrides(main.build_arg_parser().parse_args([]))


def test_cli_dry_run_skips_probe():
    """--dry-run 不应下载内核也不应启动测活"""
    with patch("freesub.fetcher.fetch_all_nodes",
               return_value=([VLESS, TROJAN], SourceHealth(os.path.join(_TMP, "sh.json")))), \
         patch("freesub.environment.ensure_xray") as env_xray, \
         patch("freesub.prober.run_probe") as runner:
        assert main.main(["--dry-run"]) == 0
        assert not env_xray.called, "--dry-run 不该下载内核"
        assert not runner.called, "--dry-run 不该测活"


def test_cli_rejects_empty_result_over_half():
    """空结果保护：本轮节点数跌破上一版一半时必须中止导出并返回非零

    注意 main.py 用 from ... import 绑定了函数名，因此必须 patch main 自身的引用，
    patch 源模块属性是拦不住的。
    """
    with patch("freesub.fetcher.fetch_all_nodes",
               return_value=([VLESS, TROJAN], SourceHealth(os.path.join(_TMP, "sh2.json")))), \
         patch("freesub.environment.ensure_xray", return_value="xray"), \
         patch("freesub.environment.ensure_mmdb"), \
         patch("freesub.prober.run_probe", return_value=[]), \
         patch("freesub.classifier._get_readers"), \
         patch("freesub.classifier._close_all_readers"), \
         patch.object(main, "count_published_nodes", return_value=100), \
         patch.object(main, "export_subscriptions") as exporter, \
         patch.object(main, "update_readme") as rd:
        assert main.main([]) == 1
        assert not exporter.called, "跌破阈值时不得导出，否则线上订阅被清空"
        assert not rd.called, "跌破阈值时不得改写 README"


def test_xray_path_is_platform_aware():
    """P3：路径不得硬编码 ./xray，Windows 本地调试需用 xray.exe"""
    assert config.XRAY_BIN.endswith(".exe") == config.IS_WINDOWS
    assert config.xray_archive_member().endswith(".exe") == config.IS_WINDOWS
    asset = config._xray_asset_name()
    assert asset.startswith("Xray-") and asset.endswith(".zip")
    if config.IS_WINDOWS:
        assert "windows" in asset
    elif sys.platform == "darwin":
        assert "macos" in asset
    else:
        assert "linux" in asset


def test_xray_version_fallback_on_api_failure():
    """GitHub API 不可用（限流/离线）时必须回退固定版本，不能中断整轮"""
    from freesub import environment

    with patch("freesub.environment.urllib.request.urlopen",
               side_effect=OSError("offline")):
        assert environment._resolve_xray_version() == environment.FALLBACK_XRAY_VERSION


def test_xray_version_respects_pin():
    from freesub import environment

    with patch.object(config, "XRAY_VERSION", "v1.8.20"):
        assert environment._resolve_xray_version() == "v1.8.20"


def test_mmdb_age_gate():
    """mmdb 缺失或超过 MMDB_MAX_AGE_DAYS 才重下，避免每轮白下 40MB"""
    from freesub import environment
    import time as _t

    calls = []

    def fake_dl(url, dest, timeout=120):
        calls.append(dest)
        with open(dest, "wb") as f:
            f.write(b"x")
        # 真实下载得到的是全新文件；这里保持默认 mtime（=现在）即可，
        # 但本用例需要在同一轮里制造「过期」状态，故显式回拨 mtime
        if dest == "Country.mmdb":
            old = _t.time() - 40 * 86400
            os.utime(dest, (old, old))

    with patch.object(config, "MMDB_MAX_AGE_DAYS", 30):
        # 两个库都新鲜 -> 都不该重下
        for name in ("Country.mmdb", "ASN.mmdb"):
            with open(name, "wb") as f:
                f.write(b"fresh")
        with patch.object(environment, "_safe_download", fake_dl):
            environment.ensure_mmdb()
            assert calls == [], f"新鲜的 mmdb 不该重下，却下了 {calls}"

        # Country 过期 40 天 + ASN 缺失 -> 都必须重下
            old = _t.time() - 40 * 86400
            os.utime("Country.mmdb", (old, old))
            os.remove("ASN.mmdb")
            environment.ensure_mmdb()
            assert "ASN.mmdb" in calls, f"缺失的 mmdb 必须补下，calls={calls}"
            assert "Country.mmdb" in calls, f"过期 40 天的 mmdb 必须重下，calls={calls}"


def test_xray_cache_hit_skips_download():
    """Xray_MAX_AGE_DAYS 内应复用缓存，不重复下载 ~30MB"""
    from freesub import environment
    import time as _t

    target = os.path.join(".", config.XRAY_BIN)
    open(target, "wb").write(b"fake-binary")
    with patch.object(environment, "_safe_download") as dl:
        assert environment.ensure_xray() == target
        assert not dl.called, "新鲜内核应命中缓存"


def test_missing_file_is_not_treated_as_fresh():
    """回归：文件不存在时 age 为 inf，而 `max_age <= inf` 恒为 True，
    会把「缺失」误判为「新鲜」从而跳过下载 —— CI 缓存未命中时 mmdb/xray 永远补不上。
    """
    from freesub.environment import _is_fresh

    assert _is_fresh("definitely-missing-file.mmdb", 30) is False
    with open(os.path.join(_TMP, "fresh.bin"), "wb") as f:
        f.write(b"x")
    assert _is_fresh(os.path.join(_TMP, "fresh.bin"), 30) is True
    assert _is_fresh(os.path.join(_TMP, "fresh.bin"), 0.0) is False


def test_repo_slug_detection():
    """README 里的 owner/repo 必须与环境或 git remote 一致，不能硬编码旧值"""
    from freesub import reporter

    with patch.dict(os.environ, {"GITHUB_REPOSITORY": "g1xy/freesub"}):
        assert reporter.detect_repo_slug() == ("g1xy", "freesub")
    # 无环境变量时应回落到 git remote（本仓库 origin 指向 g1xy/freesub），
    # 至少不能是文档里遗留的旧 owner
    os.environ.pop("GITHUB_REPOSITORY", None)
    slug = reporter._git_remote_slug()
    if slug:
        assert slug == "g1xy/freesub", f"git remote slug 解析异常: {slug}"
    else:
        assert config.DEFAULT_REPO == "g1xy/freesub", "无 remote 时默认值不得为旧 owner"


def test_empty_residential_artifacts_removed():
    """无家宽节点时必须删掉上一次的空壳配置，否则客户端会拉到过期家宽节点"""
    from freesub.reporter import _write_group

    clash = os.path.join(_TMP, "res-clash.yaml")
    sb = os.path.join(_TMP, "res-singbox.json")
    open(clash, "w").write("stale")
    open(sb, "w").write("stale")
    _write_group(clash, sb, [], [])
    assert not os.path.exists(clash) and not os.path.exists(sb)


def test_clash_yaml_empty_group_is_valid():
    """零节点时导出的 Clash 配置不能出现空 proxies 列表被客户端拒绝

    测试环境里 yaml 是 stub（无真实序列化），因此直接验证传入 export_clash_yaml
    的数据：零节点时必须补上内置 DIRECT 兜底节点。
    """
    import yaml as yaml_stub
    original = yaml_stub.dump
    captured = {}

    def fake_dump(data, *a, **k):
        captured["data"] = data
        return ""

    with patch.object(yaml_stub, "dump", fake_dump):
        main.export_clash_yaml([], os.path.join(_TMP, "empty.yaml"))

    data = captured["data"]
    assert data["proxies"], "零节点时不得留下空 proxies 列表（Clash 会拒绝加载）"
    assert data["proxies"][0]["name"] == "DIRECT"
    assert data["proxies"][0]["type"] == "direct"
    group = next(g for g in data["proxy-groups"] if g["name"] == "PROXIES")
    assert "DIRECT" in group["proxies"], "DIRECT 必须出现在选择组里"
    assert data["rules"] == ["MATCH,PROXIES"]

    # 有节点时不应被 DIRECT 污染
    captured.clear()
    with patch.object(yaml_stub, "dump", fake_dump):
        main.export_clash_yaml([{"name": "🇯🇵 日本 01", "type": "ss"}],
                               os.path.join(_TMP, "one.yaml"))
    assert [p["name"] for p in captured["data"]["proxies"]] == ["🇯🇵 日本 01"]


def test_ss_userinfo_url_encoded_base64():
    """回归：userinfo 常带 URL 编码（'%3D' 即 '='），未 unquote 就解码会失败

    线上样本形如 ss://Y2hhY2hhMjAtaWV0Zi...%3D@15.235.75.71:8388，
    旧实现因长度不匹配而把整段密文当成 cipher，好节点被误杀。
    """
    link = ("ss://" + base64.b64encode(b"chacha20-ietf-poly1305:FD3rD7uOsxOAsyr")
            .decode().replace("=", "%3D") + "@15.235.75.71:8388#n")
    assert "%3D" in link
    outbound, server, port, proto = parse_node(link)
    assert outbound is not None, "URL 编码的 base64 userinfo 解析失败"
    srv = outbound["settings"]["servers"][0]
    assert srv["method"] == "chacha20-ietf-poly1305", f"cipher 错误: {srv['method']}"
    assert srv["password"] == "FD3rD7uOsxOAsyr"
    assert (server, port) == ("15.235.75.71", 8388)


def test_ss_plaintext_sip002_not_mangled():
    """回归：明文 SIP002 链接的 cipher 曾被无条件 base64decode 成二进制垃圾

    线上表现是丢弃原因里出现 cipher='ywvzlti1ni1ny206...' 这类密文，
    好节点被白名单误杀。SIP002 两种写法都必须正确解析。
    """
    plaintext = "ss://aes-256-gcm:secret@8.8.8.8:8388#p"
    b64_userinfo = "ss://" + base64.b64encode(b"aes-256-gcm:secret").decode() + "@8.8.8.8:8388#q"
    whole_b64 = "ss://" + base64.b64encode(b"aes-256-gcm:secret@8.8.8.8:8388").decode() + "#r"

    for link in (plaintext, b64_userinfo, whole_b64):
        outbound, server, port, proto = parse_node(link)
        assert outbound is not None, f"{link[:44]} 解析失败"
        srv = outbound["settings"]["servers"][0]
        assert srv["method"] == "aes-256-gcm", f"{link[:44]} cipher 错误: {srv['method']}"
        assert srv["password"] == "secret", f"{link[:44]} 密码错误"
        assert (server, port) == ("8.8.8.8", 8388)


def test_ss_password_with_padding_characters():
    """base64 密码自带 '=' 填充时不能被截断

    2022-blake3 系列在 26.x 需特定密钥长度，此处用受支持的 cipher 验证解析本身。
    """
    link = "ss://" + base64.b64encode(b"aes-256-gcm:YWJjZA==").decode() + "@1.1.1.1:443#x"
    outbound, _, _, _ = parse_node(link)
    assert outbound is not None
    srv = outbound["settings"]["servers"][0]
    assert srv["method"] == "aes-256-gcm"
    assert srv["password"] == "YWJjZA==", "密码尾部的 = 填充不应丢失"


def test_ss_cipher_drop_reason_is_readable():
    """丢弃原因里的 cipher 应可读，不得是密文"""
    reset_drops()
    clear_cache()
    parse_node("ss://" + base64.b64encode(b"bf-cfb:pw").decode() + "@1.1.1.1:80#x")
    for key in snapshot_drops():
        if key.startswith("ss_unsupported_cipher"):
            cipher = key.split(":", 1)[1]
            assert cipher.isascii(), f"cipher 不应是二进制密文: {cipher!r}"
            assert ":" not in cipher and len(cipher) <= 32
            return
    raise AssertionError(f"未记录 cipher 丢弃原因: {snapshot_drops()}")


def test_ss_corrupted_userinfo_is_classified_not_leaked():
    """损坏的 userinfo（解码出二进制垃圾）应被归类丢弃，密文不得出现在丢弃原因里"""
    reset_drops()
    clear_cache()
    # 该 userinfo 解码后是二进制垃圾且无 ':'，无法确定 cipher，属于损坏数据
    garbage = "ss://y2hhy2hhmjatawv0zi1wb2x5mtmwntpl@15.235.75.71:8388#y"
    outbound, _, _, _ = parse_node(garbage)
    assert outbound is None, "损坏链接不得入库"
    for key in snapshot_drops():
        value = key.split(":", 1)[1] if ":" in key else ""
        assert value.isascii(), f"丢弃原因泄漏了密文: {key}"
    assert any(k.startswith(("ss_userinfo_undecodable", "ss_cipher_unresolvable"))
               for k in snapshot_drops()), snapshot_drops()


# ================================================================ 内核兼容性

def test_no_removed_allowinsecure_in_kernel_config():
    """回归：Xray-core 26.x 已移除 allowInsecure（改为 pinnedPeerCertSha256）

    原实现所有 TLS 配置都带 allowInsecure，在新版内核上会让**整批配置启动失败**，
    200 个节点一起完蛋。这里断言内核配置里不得出现该字段。
    """
    for link in (VLESS, TROJAN, HY2, VLESS_XHTTP, VLESS_GRPC):
        outbound, _, _, _ = parse_node(link)
        cleaned = strip_private_keys(outbound)
        blob = json.dumps(cleaned)
        assert "allowInsecure" not in blob, f"{link[:32]} 内核配置仍含已移除的 allowInsecure"
        # TLS 必须保留 serverName，否则 sni 失效
        if cleaned.get("streamSettings", {}).get("security") in ("tls", "reality"):
            tls = cleaned["streamSettings"].get("tlsSettings") or \
                cleaned["streamSettings"].get("realitySettings")
            assert tls.get("serverName"), f"{link[:32]} 缺少 serverName"


def test_reality_public_key_written_to_both_field_names():
    """26.x 的 REALITY 公钥字段是 password（1.8.x 为 publicKey）

    实测 26.3.27 两者都接受，但只用 password 可避免歧义；导出侧必须取到同一个 key。
    """
    outbound, _, _, _ = parse_node(VLESS_GRPC)
    reality = outbound["streamSettings"]["realitySettings"]
    assert reality["password"] == "PUBKEY", "26.x 内核读 password 字段"
    # Clash / sing-box 导出侧应取到同一个 key
    assert to_clash_proxy(VLESS_GRPC, "X")["reality-opts"]["public-key"] == "PUBKEY"
    assert to_singbox_outbound(VLESS_GRPC, "X")["tls"]["reality"]["public_key"] == "PUBKEY"


def test_kernel_unprobeable_protocols_excluded():
    """回归：Xray 26.x 移除了内核级 hysteria2 / tuic

    这类节点若进内核配置会返回 unknown config id 并导致整批启动失败，
    必须分流到 sing-box 补充测活，但仍要保留给 Clash / sing-box 导出。
    """
    for link, reason in ((HY2, "kernel_unsupported_protocol:hysteria2"),):
        outbound, _, _, _ = parse_node(link)
        assert outbound is not None, f"{link[:24]} 应保留解析（导出仍需要）"
        assert is_kernel_probeable(outbound) is False, f"{link[:24]} 不该进 Xray 内核配置"

        # 不能占用 inbound（否则整批被它拖垮）
        cfg, pairs = build_batch_config([(link, "1.1.1.1", 443, "v")], [20100])
        assert not pairs, "内核不可测活的节点不得占用 inbound"
        assert cfg is None, "全部节点都不可测活时不应生成配置"

        # 但 Clash / sing-box 导出必须仍然可用
        assert to_clash_proxy(link, "X") is not None, f"{link[:24]} Clash 导出被误伤"
        assert to_singbox_outbound(link, "X") is not None, f"{link[:24]} sing-box 导出被误伤"

        reset_drops()
        clear_cache()
        build_batch_config([(link, "1.1.1.1", 443, "v")], [20100])
        assert reason in snapshot_drops(), f"丢弃原因应记为 {reason}，实际 {snapshot_drops()}"


def test_hysteria2_routed_to_singbox_probe():
    """hy2 节点应被分流到 sing-box，而不是直接丢弃"""
    from freesub import sbprober

    cfg = sbprober.build_config(HY2, "probe", 20777)
    assert cfg is not None, "sing-box 应能生成 hy2 测活配置"
    assert cfg["outbounds"][0]["type"] == "hysteria2"
    assert cfg["route"]["final"] == "probe"
    assert cfg["inbounds"][0]["listen_port"] == 20777


def test_kernel_probeable_accepted():
    """常见传输层必须仍然可测活，不能被兼容性过滤误伤"""
    for link in (VLESS, VLESS_GRPC, VLESS_HTTPUP, VLESS_XHTTP, TROJAN, SS, VMESS):
        outbound, _, _, _ = parse_node(link)
        assert is_kernel_probeable(outbound) is True, f"{link[:32]} 被误判为内核不可用"


def test_mixed_batch_drops_only_unsupported():
    """混合批次里只有 Xray 内核不注册的协议被剔除，其余照常测活

    h2/quic/kcp 已在解析阶段降级为 raw，因此只有内核级 hysteria2 被排除。
    """
    quic = "vmess://" + base64.b64encode(json.dumps({
        "v": "2", "add": "9.9.9.9", "port": "443", "id": UUID, "aid": "0",
        "net": "quic", "tls": "tls"}).encode()).decode()
    batch = [
        (VLESS, "5.6.7.8", 443, "vless"),
        (quic, "9.9.9.9", 443, "vmess"),
        (TROJAN, "1.2.3.4", 443, "trojan"),
        (HY2, "7.7.7.7", 443, "hysteria2"),
        (SS, "8.8.8.8", 8388, "ss"),
    ]
    # quic 已降级为 raw 可测活，只有内核级 hysteria2 被排除
    cfg, pairs = build_batch_config(batch, [20101, 20102, 20103, 20104, 20105])
    assert len(pairs) == 4, f"应保留 4 个可测活节点，实际 {len(pairs)}"
    assert len(cfg["inbounds"]) == 4
    assert len(cfg["outbounds"]) == 5  # 4 节点 + direct


def test_xray_rejects_none_of_our_kernel_configs():
    """集成测试：生成的内核配置必须能被真实 xray 二进制接受

    这是唯一能拦住「新版内核破坏性变更」的测试 —— 单测只验证字段存在，
    但内核对未知/已移除字段是启动即失败。此用例在无内核时自动跳过。
    """
    import subprocess
    import uuid as _uuid

    # 测试已 chdir 到临时目录，内核在项目根；Windows 上必须给绝对路径
    binary = os.path.join(_PROJECT_DIR, config.XRAY_BIN)
    if not os.path.exists(binary):
        print("      (skip: 本地无 xray 内核)")
        return
    version = subprocess.run([binary, "version"], capture_output=True, timeout=30)
    if version.returncode != 0:
        print("      (skip: xray 内核不可执行)")
        return

    pk = base64.urlsafe_b64encode(b"x" * 32).decode().rstrip("=")
    cases = [
        VLESS,
        VLESS_GRPC.replace("PUBKEY", pk),
        VLESS_HTTPUP,
        VLESS_XHTTP,
        TROJAN,
        SS,
        VMESS,
        VMESS_GRPC,
        f"vless://{UUID}@5.6.7.8:443?type=tcp&headerType=http&host=a.com&path=%2Fp#t",
        f"vless://{UUID}@5.6.7.8:443?security=reality&pbk={pk}&flow=xtls-rprx-vision&type=tcp#n",
    ]
    failures = []
    for link in cases:
        outbound, _, _, proto = parse_node(link)
        if not is_kernel_probeable(outbound):
            continue
        cfg, _ = build_batch_config([(link, "5.6.7.8", 443, proto)], [20200])
        path = os.path.join(_TMP, f"it_{_uuid.uuid4().hex}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        proc = subprocess.run([binary, "run", "-test", "-c", path], capture_output=True, timeout=60)
        if proc.returncode != 0:
            msg = ((proc.stderr or b"").decode(errors="ignore") or
                   (proc.stdout or b"").decode(errors="ignore"))
            failures.append(f"{link[:40]}... -> {msg.strip().splitlines()[-1][:160] if msg.strip() else 'rc=%d' % proc.returncode}")
    assert not failures, "真实内核拒绝了以下配置:\n    " + "\n    ".join(failures)


def test_xray_version_follows_latest():
    """项目已适配 Xray 26.x，默认跟随 latest

    解析层按 26.x 语义生成配置（无 allowInsecure / QUIC / mKCP / 内核 hy2），
    并有真实内核集成测试守住这条线，因此可以安全跟随最新版。
    """
    assert config.XRAY_VERSION == "latest", (
        f"默认内核版本为 {config.XRAY_VERSION}，应跟随 latest 以保持安全更新")
    assert config.SINGBOX_VERSION == "latest", "sing-box 补充内核同样跟随 latest"


def test_singbox_insecure_field_is_not_kernel_field():
    """sing-box 的 insecure 是自有字段，不得被误当作已被移除的 allowInsecure"""
    sb = to_singbox_outbound(VLESS, "X")
    assert sb["tls"]["insecure"] is True
    assert "allowInsecure" not in json.dumps(sb)


def test_removed_ciphers_dropped_at_parse_time():
    """回归：26.x 移除了 aes-*-cfb / rc4-md5 / aes-*-ctr 等 cipher

    这些 cipher 若进内核批次会让整批 200 个节点一起启动失败，
    因此在解析阶段就丢弃（连候选都不进），比「解析后再判不可测活」更省。
    """
    for cipher in ("aes-256-cfb", "rc4-md5", "aes-128-cfb",
                   "aes-256-ctr", "chacha20-poly1305", "2022-blake3-aes-256-gcm"):
        reset_drops()
        clear_cache()
        link = "ss://" + base64.b64encode(f"{cipher}:pw".encode()).decode() + "@1.1.1.1:80#x"
        outbound, _, _, _ = parse_node(link)
        assert outbound is None, f"{cipher} 在 26.x 不可用，应在解析阶段丢弃"
        assert any(k.startswith("ss_unsupported_cipher") for k in snapshot_drops()), snapshot_drops()

    # 内核仍支持的必须保留
    for cipher in ("aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"):
        clear_cache()
        link = "ss://" + base64.b64encode(f"{cipher}:pw".encode()).decode() + "@1.1.1.1:8388#x"
        assert parse_node(link)[0] is not None, f"{cipher} 是 26.x 支持的，不该被丢"


def test_reality_with_ws_downgraded_but_exported():
    """REALITY 只允许 RAW / XHTTP / gRPC（26.x），配 ws 会启动失败 -> 降级为 raw"""
    pk = base64.urlsafe_b64encode(b"x" * 32).decode().rstrip("=")
    reality_ws = f"vless://{UUID}@1.1.1.1:443?security=reality&pbk={pk}&type=ws&path=%2Fw#r"
    outbound, _, _, _ = parse_node(reality_ws)
    assert outbound is not None
    stream = outbound["streamSettings"]
    assert stream["network"] == "raw", "REALITY+ws 应在内核侧降级为 raw"
    assert is_kernel_probeable(outbound) is True, "降级后即可测活"
    assert stream["_originalNetwork"] == "ws", "原传输层应保留供导出"
    # 导出侧仍按原始 ws 配置（客户端支持 REALITY+ws）
    clash = to_clash_proxy(reality_ws, "X")
    assert clash is not None and clash.get("network") == "ws"
    assert to_singbox_outbound(reality_ws, "X") is not None


def test_http2_transport_downgraded_to_raw():
    """回归：26.x 移除了 HTTP/2 (h2/http) 传输

    降级为 raw 后这些节点仍可被 Xray 测活（比整类丢弃好），
    同时 Clash / sing-box 导出仍拿到原始 http 传输。
    """
    for typ in ("http", "h2"):
        link = f"vless://{UUID}@1.1.1.1:443?type={typ}&path=%2Fp&host=h.com&security=tls&sni=x.com#x"
        outbound, _, _, _ = parse_node(link)
        assert outbound is not None
        assert is_kernel_probeable(outbound) is True, f"{typ} 降级后应可测活"
        stream = outbound["streamSettings"]
        assert stream["network"] == "raw"
        assert "httpSettings" not in stream
        clash = to_clash_proxy(link, "X")
        assert clash["network"] == "http", f"{typ} Clash 应保留 http 传输"


def test_reality_with_allowed_transports_kept():
    """REALITY 搭配 RAW/XHTTP/gRPC 必须保留"""
    pk = base64.urlsafe_b64encode(b"x" * 32).decode().rstrip("=")
    for typ in ("tcp", "xhttp", "grpc"):
        link = f"vless://{UUID}@1.1.1.1:443?security=reality&pbk={pk}&type={typ}#r"
        outbound, _, _, _ = parse_node(link)
        assert is_kernel_probeable(outbound) is True, f"REALITY+{typ} 应可测活"


# ================================================================ 运行器

def _run_all() -> int:
    failed = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {name}: {e}")
        except Exception as e:
            failed += 1
            print(f"  ERROR {name}: {type(e).__name__}: {e}")
    print(f"\n{'全部通过' if failed == 0 else f'{failed} 项失败'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
