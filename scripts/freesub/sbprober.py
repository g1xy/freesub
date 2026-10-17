"""基于 sing-box 的测活探针：用于 Xray 26.x 不支持的协议（hysteria2 / tuic）。

与 xray 探针的关键差异：
  - sing-box 的每个 inbound 只能绑定一个 outbound，无法像 xray 那样靠
    routing.inboundTag 做「单实例多入站」，因此这里每节点一个实例，
    但 hy2 节点本身占比不高（实测 5426 个中 270 个），可以接受
  - 配置用 `sing-box check -c` 先做静态校验，避免非法配置导致整批失败

实测结论（Xray 26.3.27 + sing-box 1.14.3）：
  sing-box check 通过 hy2 基础 / hy2+obfs / hy2:// 前缀三种写法，
  并已用真实节点完成 HTTPS 204 握手（status=204，2584ms）。
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import requests

from . import config
from .exporters import to_singbox_outbound
from .logutil import get_logger, record_drop

log = get_logger("sbprobe")

AliveNode = Tuple[str, str, int, str, str, int, bool]
_SINGBOX_BIN = config.SINGBOX_BIN


def set_singbox_binary(path: str) -> None:
    global _SINGBOX_BIN
    _SINGBOX_BIN = path


def _bin() -> str:
    return _SINGBOX_BIN if os.path.isabs(_SINGBOX_BIN) else os.path.abspath(_SINGBOX_BIN)


def allocate_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port_ready(port: int, deadline_sec: Optional[float] = None) -> bool:
    deadline = deadline_sec if deadline_sec is not None else config.SINGBOX_PORT_READY_TIMEOUT
    end = time.time() + deadline
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def build_config(node_link: str, tag: str, listen_port: int) -> Optional[Dict[str, Any]]:
    """生成 sing-box 测活配置（mixed 入站 -> 指定 outbound）"""
    outbound = to_singbox_outbound(node_link, tag)
    if not outbound:
        return None
    return {
        "log": {"level": "warn"},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1",
                      "listen_port": listen_port}],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"rules": [{"inbound": ["in"], "outbound": tag}],
                  "final": tag, "auto_detect_interface": True},
    }


def validate_config(config_dict: Dict[str, Any], path: str) -> bool:
    """用 sing-box check 静态校验配置

    只写文件、不删除 —— 调用方紧接着要用同一份文件 `sing-box run`，
    清理由调用方负责。
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config_dict, f)
    try:
        proc = subprocess.run([_bin(), "check", "-c", path], capture_output=True, timeout=60)
        return proc.returncode == 0
    except FileNotFoundError:
        return False
    except Exception as exc:  # noqa: BLE001
        log.debug("sing-box 配置校验异常: %s", exc)
        return True


def probe_via_socks(node_link: str, server: str, port: int, proto: str,
                    listen_port: int) -> Optional[AliveNode]:
    """经 sing-box 建立的代理完成真实 HTTPS 握手并获取落地 IP"""
    proxies = {"http": f"socks5h://127.0.0.1:{listen_port}",
               "https": f"socks5h://127.0.0.1:{listen_port}"}
    delays: List[int] = []
    # hy2 走 UDP，正常握手很快；超时过长只会让死节点白占并发槽
    timeout = config.SINGBOX_PROBE_TIMEOUT
    for _ in range(config.PROBE_REPEAT):
        try:
            start = time.time()
            resp = requests.get(config.PROBE_TEST_URL, proxies=proxies, timeout=timeout)
            if resp.status_code not in (200, 204):
                record_drop(f"sb_probe_unexpected_status:{resp.status_code}")
                return None
            delays.append(int((time.time() - start) * 1000))
        except Exception as exc:  # noqa: BLE001
            record_drop(f"sb_probe_failed:{type(exc).__name__}")
            return None

    delay_ms = sorted(delays)[len(delays) // 2]
    if not (config.MIN_DELAY_MS < delay_ms < config.MAX_DELAY_MS):
        record_drop("sb_probe_delay_out_of_range")
        return None

    exit_ip, confirmed = "", False
    for check_url in config.EXIT_IP_URLS:
        try:
            r = requests.get(check_url, proxies=proxies,
                             timeout=min(config.EXIT_IP_TIMEOUT, timeout))
            if r.status_code == 200 and r.json().get("ip"):
                exit_ip = r.json()["ip"]
                confirmed = True
                break
        except Exception:  # noqa: BLE001
            continue
    if not exit_ip:
        record_drop("sb_probe_no_confirmed_exit_ip")
        try:
            exit_ip = socket.gethostbyname(server)
        except Exception:  # noqa: BLE001
            exit_ip = server

    return (node_link, server, port, proto, exit_ip, delay_ms, confirmed)


def probe_node(node_link: str, server: str, port: int, proto: str) -> Optional[AliveNode]:
    """单节点起一个 sing-box 实例完成测活"""
    listen_port = allocate_port()
    cfg = build_config(node_link, "probe", listen_port)
    if not cfg:
        record_drop("sb_config_build_failed")
        return None

    # 写在系统临时目录而非工作区，避免污染仓库 / 异常残留
    fd, cfg_path = tempfile.mkstemp(prefix="sb_", suffix=".json")
    os.close(fd)
    if not validate_config(cfg, cfg_path):
        _try_remove(cfg_path)
        record_drop("sb_config_invalid")
        return None

    proc = subprocess.Popen([_bin(), "run", "-c", cfg_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_port_ready(listen_port):
            record_drop("sb_port_not_ready")
            return None
        return probe_via_socks(node_link, server, port, proto, listen_port)
    finally:
        _kill(proc)
        _try_remove(cfg_path)


def _kill(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:  # noqa: BLE001
        try:
            proc.kill()
            proc.wait(timeout=3)
        except Exception:  # noqa: BLE001
            pass


def _try_remove(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def run_probe(items: List[Tuple[str, str, int, str]],
              workers: Optional[int] = None,
              budget_sec: Optional[float] = None) -> List[AliveNode]:
    """并发测活 sing-box 支持的节点（每节点一个实例）

    items 为 (link, server, port, proto) 四元组。

    并发说明：sing-box 每个实例 = 1 进程 + 1 端口，资源占用远小于
    「单实例多入站」的 xray 模式，因此并发可以给得较高（默认 PROBE_WORKERS）。
    同时受独立时间预算约束，避免 hy2 拖垮整轮。
    """
    if not items:
        return []
    pool_size = workers or config.PROBE_WORKERS
    budget = budget_sec if budget_sec is not None else config.SINGBOX_BUDGET_SEC
    log.info("sing-box 补充测活 %d 个节点（每节点一个实例，并发 %d，预算 %ds）",
             len(items), pool_size, int(budget))

    alive: List[AliveNode] = []
    start = time.time()
    with ThreadPoolExecutor(max_workers=pool_size) as executor:
        futures = {executor.submit(probe_node, *item): item for item in items}
        done_count = 0
        for future in as_completed(futures):
            done_count += 1
            try:
                res = future.result()
            except Exception as exc:  # noqa: BLE001
                record_drop(f"sb_probe_exception:{type(exc).__name__}")
                continue
            if res:
                alive.append(res)
            if done_count % 20 == 0 and time.time() - start > budget:
                pending = len(futures) - done_count
                log.warning("sing-box 补充测活已达 %.0fs 预算，跳过剩余 %d 个节点",
                            time.time() - start, max(0, pending))
                for f in futures:
                    f.cancel()
                break

    log.info("sing-box 测活完成：真实可用 %d 个（耗时 %ds）",
             len(alive), int(time.time() - start))
    return alive
