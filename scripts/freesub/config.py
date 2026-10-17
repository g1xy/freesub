"""集中配置：可调参数、节点源、地理/ASN 判定表、路径与平台适配。

所有模块从这里取常量，避免原先 main.py 单文件里散落的魔法值。
所有可调参数均支持环境变量覆盖，便于在不同 runner 上调优而无需改代码。
"""
from __future__ import annotations

import os
import sys
from typing import Dict, FrozenSet, List, Set, Tuple

# ---------------------------------------------------------------- 平台判定
# 必须最先定义：下方的内核二进制名与官方发布包名都依赖它
IS_WINDOWS = sys.platform.startswith("win")

# ---------------------------------------------------------------- 测活调优参数
PROBE_BATCH_SIZE = int(os.environ.get("PROBE_BATCH_SIZE", "200"))
PROBE_WORKERS = int(os.environ.get("PROBE_WORKERS", "25"))
PROBE_TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "6.5"))
TOTAL_BUDGET_SEC = int(os.environ.get("TOTAL_BUDGET_SEC", "2100"))
MAX_CANDIDATES = int(os.environ.get("MAX_CANDIDATES", "8000"))
MIN_DELAY_MS = int(os.environ.get("MIN_DELAY_MS", "10"))
MAX_DELAY_MS = int(os.environ.get("MAX_DELAY_MS", "6300"))
# 单节点重复探测次数（取中位数），>1 时更稳但耗时成倍上升
PROBE_REPEAT = max(1, int(os.environ.get("PROBE_REPEAT", "1")))
# 批量 inbound 的启动等待上限（秒）。大批量时内核监听端口需要更久，
# 超时会自动拆小批重试而不是丢弃整批。
PORT_READY_TIMEOUT = float(os.environ.get("PORT_READY_TIMEOUT", "20"))
# 拆批重试的下限批次大小
MIN_BATCH_SIZE = int(os.environ.get("MIN_BATCH_SIZE", "8"))

# 抓源与分类
SOURCE_TIMEOUT_SEC = float(os.environ.get("SOURCE_TIMEOUT_SEC", "25"))
SOURCE_FETCH_WORKERS = int(os.environ.get("SOURCE_FETCH_WORKERS", "10"))
CLASSIFY_WORKERS = int(os.environ.get("CLASSIFY_WORKERS", "30"))
MAX_EXPAND_BYTES = int(os.environ.get("MAX_EXPAND_BYTES", str(8 * 1024 * 1024)))
# 连续失败多少次后跳过该源（本轮仍会保留至少一个可用源，防止全被跳过）
SOURCE_FAIL_THRESHOLD = int(os.environ.get("SOURCE_FAIL_THRESHOLD", "5"))

# 内核与数据库
#
# 已适配 Xray-core 26.x（能力矩阵由真实二进制 xray run -test 逐项实测得出，
# 见 OPTIMIZATION.md「26.x 适配」小节）：
#   协议    : vless / vmess / trojan / shadowsocks / socks / http / freedom / blackhole
#   传输层  : raw(tcp) / ws / grpc / httpupgrade / xhttp
#   已移除  : http(h2) / quic / kcp(mKCP) / 内核级 hysteria2 / 内核级 tuic
#   REALITY : 仅允许搭配 raw / xhttp / grpc（配 ws 或 httpupgrade 会启动失败）
#   TLS     : allowInsecure 已移除，改为 pinnedPeerCertSha256（本项目不写该字段）
#   ss cipher: 仅 aes-*-gcm / chacha20-ietf-poly1305 / xchacha20-ietf-poly1305 / none
#
# 默认跟随 latest；解析层已按 26.x 语义生成配置。若要用 1.8.x 需改回旧语义，
# 不要直接改版本号 —— 见 OPTIMIZATION.md。
XRAY_VERSION = os.environ.get("XRAY_VERSION", "latest")
XRAY_MAX_AGE_DAYS = float(os.environ.get("XRAY_MAX_AGE_DAYS", "7"))

# sing-box：专门测活 Xray 26.x 已移除的内核级协议（hysteria2 / tuic）。
# 这类节点占公开源约 5%，丢掉损失一整类协议，因此引入补充内核。
SINGBOX_VERSION = os.environ.get("SINGBOX_VERSION", "latest")
SINGBOX_MAX_AGE_DAYS = float(os.environ.get("SINGBOX_MAX_AGE_DAYS", "30"))
SINGBOX_BATCH_SIZE = int(os.environ.get("SINGBOX_BATCH_SIZE", "100"))
# sing-box 补充测活的独立时间预算（秒），避免 hy2 阶段拖垮整轮
SINGBOX_BUDGET_SEC = int(os.environ.get("SINGBOX_BUDGET_SEC", "420"))
# hy2 走 UDP，正常握手在 1s 内；超时设太长只会让死节点白占并发槽
SINGBOX_PROBE_TIMEOUT = float(os.environ.get("SINGBOX_PROBE_TIMEOUT", "4.0"))
SINGBOX_PORT_READY_TIMEOUT = float(os.environ.get("SINGBOX_PORT_READY_TIMEOUT", "8"))
XRAY_BIN = os.environ.get("XRAY_BIN") or ("xray.exe" if IS_WINDOWS else "xray")
SINGBOX_BIN = os.environ.get("SINGBOX_BIN") or ("sing-box.exe" if IS_WINDOWS else "sing-box")
MMDB_MAX_AGE_DAYS = float(os.environ.get("MMDB_MAX_AGE_DAYS", "30"))
PROBE_TEST_URL = os.environ.get("PROBE_TEST_URL", "https://www.google.com/generate_204")
PROBE_TEST_HOST = os.environ.get("PROBE_TEST_HOST", "www.google.com")

EXIT_IP_URLS: Tuple[str, ...] = (
    os.environ.get("EXIT_IP_URL_1", "https://api.ipify.org?format=json"),
    os.environ.get("EXIT_IP_URL_2", "https://ip.seeip.org/json"),
)
EXIT_IP_TIMEOUT = float(os.environ.get("EXIT_IP_TIMEOUT", "3.0"))

# ---------------------------------------------------------------- 节点源
SOURCE_URLS: List[str] = [
    "https://wild-cloud-9893.heleimail.workers.dev",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-TW.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",
    "https://raw.githubusercontent.com/10ium/HiN-VPN/main/subscription/base64/mix",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/protocols/hysteria",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/security/tls",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://open.heleimail.workers.dev/",
    "https://www.ermao.net/sub/v2ray/ermao.net",
]

# ---------------------------------------------------------------- 输出路径
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "output")
COUNTRY_DIR = os.path.join(OUTPUT_DIR, "by-country")
RESIDENTIAL_COUNTRY_DIR = os.path.join(OUTPUT_DIR, "residential-by-country")
SOURCES_STATUS_FILE = os.path.join(OUTPUT_DIR, "sources_status.json")
META_FILE = os.path.join(OUTPUT_DIR, "meta.json")
README_FILE = os.environ.get("README_FILE", "README.md")

DEFAULT_REPO = os.environ.get("FREESUB_REPO", "g1xy/freesub")


def ensure_directories() -> None:
    """仅在真正要写盘时调用（原先在 import 时建目录属于副作用）"""
    for path in (OUTPUT_DIR, COUNTRY_DIR, RESIDENTIAL_COUNTRY_DIR):
        os.makedirs(path, exist_ok=True)


# ---------------------------------------------------------------- 平台适配
# 注：IS_WINDOWS 已在文件顶部定义（内核二进制名依赖它）
def _xray_asset_name() -> str:
    """按运行平台选择 Xray-core 官方发布包名"""
    import platform

    machine = (platform.machine() or "").lower()
    is_arm = machine in ("arm64", "aarch64")
    if IS_WINDOWS:
        return "Xray-windows-64.zip"
    if sys.platform == "darwin":
        return "Xray-macos-arm64-v8a.zip" if is_arm else "Xray-macos-64.zip"
    return "Xray-linux-arm64-v8a.zip" if is_arm else "Xray-linux-64.zip"


def xray_archive_member() -> str:
    return "xray.exe" if IS_WINDOWS else "xray"


# ---------------------------------------------------------------- 地理与 ASN
CLOUDFLARE_IP_NETWORKS: List[str] = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

DATACENTER_ASNS: FrozenSet[int] = frozenset({
    13335, 16509, 14618, 15169, 396982, 8075, 24940, 16276,
    14061, 31898, 63949, 45102, 132203, 20473, 60068, 55081,
    197540, 51167, 8560, 42708, 201814, 49981, 212238, 46652,
    141995, 200019, 136907, 39351, 9009, 174, 3356, 1299, 2914,
    199180, 202051, 62240, 49304, 34665, 209242, 219337, 44477,
    200651, 202685, 210644, 205628, 51852, 204544, 397373,
})

IDC_KEYWORDS: Tuple[str, ...] = (
    "hosting", "datacenter", "data center", "cloud", "server", "vps",
    "dedicated", "compute", "colo", "digitalocean", "linode", "ovh",
    "hetzner", "choopa", "vultr", "alibaba", "tencent", "amazon", "aws",
    "google", "microsoft", "oracle", "fastly", "cloudflare", "akamai",
    "netgrid", "m247", "leaseweb", "contabo", "cogent", "zenlayer",
    "ucloud", "lagom", "ipvolume", "hostkey", "selectel", "quadranet",
    "buyvm", "play2go", "fzco",
)

TRUE_RESIDENTIAL_ASNS: FrozenSet[int] = frozenset({
    3462, 9924, 17709, 4780, 18049,
    9269, 3491, 4760, 9304, 17816,
    2516, 4713, 9605, 17511, 17676,
    9318, 4766,
    701, 702, 7922, 20115, 2856, 5089, 5607, 3320, 3209,
})

RESIDENTIAL_WHITELIST_KEYWORDS: Tuple[str, ...] = (
    "broadband", "dynamic", "pppoe", "cust", "dial", "user", "home",
    "residential", "ftth", "cable", "dsl", "consumer",
    "chunghwa", "hinet", "cht", "data communication business group",
    "taiwan fixed network", "kbro", "far eastone", "tfn",
    "hkbn", "hong kong broadband", "pccw", "hkt", "hgc", "smartone",
    "so-net", "kddi", "softbank", "ocn", "plala", "sk broadband", "korea telecom",
    "comcast", "charter", "at&t", "verizon", "spectrum", "cox", "vodafone",
    "deutsche telekom", "telekom", "orange", "bt-central", "virgin media",
)

COUNTRY_NAMES: Dict[str, str] = {
    "HK": "中国香港 (Hong Kong)",
    "TW": "中国台湾 (Taiwan)",
    "JP": "日本 (Japan)",
    "SG": "新加坡 (Singapore)",
    "US": "美国 (United States)",
    "KR": "韩国 (South Korea)",
    "DE": "德国 (Germany)",
    "GB": "英国 (United Kingdom)",
    "CA": "加拿大 (Canada)",
    "FR": "法国 (France)",
    "NL": "荷兰 (Netherlands)",
    "RU": "俄罗斯 (Russia)",
    "IN": "印度 (India)",
    "AU": "澳大利亚 (Australia)",
    "IT": "意大利 (Italy)",
    "ES": "西班牙 (Spain)",
    "TR": "土耳其 (Turkey)",
    "AE": "阿联酋 (UAE)",
    "OTHER": "其他地区 (Other)",
}

# Xray 26.x 实际支持的 shadowsocks 加密方式（由真实内核逐项 xray -test 实测）。
#   - aes-*-ctr / aes-*-cfb / rc4-md5 / chacha20-poly1305 → unknown cipher method
#   - 2022-blake3-* 需要特定长度密钥，常规链接的密码长度几乎都不满足，
#     实测同样返回失败，因此一并剔除（保留在解析阶段丢弃，避免整批配置失败）
VALID_SS_CIPHERS: FrozenSet[str] = frozenset({
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "none",
})

# 26.x 已移除或需特殊密钥的 cipher；解析阶段提前丢弃，避免整批启动失败
LEGACY_ONLY_SS_CIPHERS: FrozenSet[str] = frozenset({
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "rc4-md5",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "chacha20-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
})

# Xray 核心完全不支持的 shadowsocks 插件（obfs-local / v2ray-plugin 等）。
# 这类节点无法通过真实测活，出于「只发布验证过的节点」原则直接丢弃，不浪费测活预算。
SS_PLUGIN_PREFIXES: Tuple[str, ...] = ("obfs-local", "v2ray-plugin", "shadow-tls")

# 允许出现在 Xray streamSettings.network 中的传输层
SUPPORTED_NETWORKS: FrozenSet[str] = frozenset({
    "tcp", "raw", "ws", "websocket", "grpc", "gun", "httpupgrade", "xhttp",
})

# 26.x 移除了 QUIC、HTTP/2(h2/http) 传输、mKCP，以及内核级 hysteria2 / tuic。
# 这些协议若进内核配置会返回 unknown config id / removed 导致**整批启动失败**，
# 需在构建配置时排除（它们对 Clash / sing-box 仍然有效，照常导出）。
KERNEL_UNSUPPORTED_PROTOCOLS: FrozenSet[str] = frozenset({
    "quic", "mkcp", "hysteria2", "tuic",
})
KERNEL_UNSUPPORTED_NETWORKS: FrozenSet[str] = frozenset({
    "quic", "kcp", "mkcp", "http", "h2",
})

# 26.x 下 REALITY 仅允许搭配这些传输层
REALITY_ALLOWED_NETWORKS: FrozenSet[str] = frozenset({"tcp", "raw", "xhttp", "grpc"})

# 内核兼容性：Xray 26+ 要求用 pinnedPeerCertChainSha256 取代已移除的 allowInsecure。
# 统一以「只写 serverName、不写证书校验开关」的方式兼容两代内核 ——
# 免费节点普遍自签/证书过期，实践中没有可靠手段做证书固定。
TLS_SKIP_VERIFY_COMPAT: bool = os.environ.get(
    "TLS_SKIP_VERIFY_COMPAT", "1") not in ("0", "false", "False")


def is_cloudflare_cdn_ip(ip_str: str) -> bool:
    import ipaddress

    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip_obj in ipaddress.ip_network(net) for net in CLOUDFLARE_IP_NETWORKS)


def get_country_flag(country_code: str) -> str:
    if not country_code or country_code.upper() in ("OTHER", "ZZ", "XX", "T1"):
        return "🌐"
    cc = country_code.upper()
    if len(cc) == 2 and cc.isalpha():
        return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)
    return "🌐"


def is_supported_network(network: str) -> bool:
    return (network or "tcp").lower() in SUPPORTED_NETWORKS


def node_protocol(node_link: str) -> str:
    """从链接前缀取协议名，用于丢弃原因归类"""
    if node_link.startswith(("hy2://", "hysteria2://")):
        return "hysteria2"
    if "://" in node_link:
        return node_link.split("://", 1)[0].lower()
    return "unknown"


def supported_cipher_set() -> Set[str]:
    return set(VALID_SS_CIPHERS)
