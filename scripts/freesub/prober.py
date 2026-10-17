"""真实测活：用 Xray-core 建立实际代理隧道并完成 HTTPS 双向传输握手。

架构要点（相对初版的改进）：
  1. 单 Xray 实例承载整批节点：每节点独占一个 socks inbound，routing 按
     inboundTag 绑定 outboundTag，避免逐节点 fork 进程（25 节点从 25 进程降到 3）
  2. 批量配置先经 `xray run -test` 校验；非法则二分隔离坏节点，
     不让一个畸形节点拖垮整批 200 个
  3. 端口就绪用轮询探测替代固定 sleep(0.35)，避免启动慢导致假阴性
  4. 全部超时/上限可用环境变量覆盖，且受全局时间预算约束
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
from .logutil import get_logger, record_drop
from .parse import (
    is_kernel_probeable, kernel_incompatibility, parse_node, strip_private_keys,
)

log = get_logger("probe")

NodeTuple = Tuple[str, str, int, str]
AliveNode = Tuple[str, str, int, str, str, int, bool]

_XRAY_BIN = config.XRAY_BIN


def _xray_path() -> str:
    """返回可被 subprocess 直接执行的内核绝对路径

    Windows 上相对路径会触发 WinError 216，必须给绝对路径。
    """
    if os.path.isabs(_XRAY_BIN):
        return _XRAY_BIN
    return os.path.abspath(_XRAY_BIN)


def temp_config_path(prefix: str = "xray") -> str:
    """在系统临时目录里分配一个配置路径。

    刻意不写在工作区：配置是纯临时产物，写在仓库里既污染 git 状态，
    也容易在异常路径下残留（每轮几百个文件的量）。
    """
    fd, path = tempfile.mkstemp(prefix=f"{prefix}_", suffix=".json")
    os.close(fd)
    return path


def set_xray_binary(path: str) -> None:
    global _XRAY_BIN
    _XRAY_BIN = path


# ---------------------------------------------------------------- 端口与进程

def allocate_ports(count: int) -> List[int]:
    """批量申请临时端口（申请后立即释放，Xray 随即接管监听）"""
    ports: List[int] = []
    for _ in range(count):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            ports.append(s.getsockname()[1])
    return ports


def wait_ports_ready(ports: List[int], deadline_sec: float = 20.0,
                      require_all: bool = True) -> bool:
    """轮询等待 Xray 入站就绪，替代不可靠的固定 sleep。

    require_all=True 时要求全部端口就绪；False 时只要多数就绪即返回（用于榨干
    已启动的节点，内核对同时监听数有上限时允许部分失败）。
    """
    if not ports:
        return False
    probe_ports = ports[:min(5, len(ports))]
    target = len(probe_ports) if require_all else max(1, len(probe_ports) // 2)
    end = time.time() + deadline_sec
    while time.time() < end:
        ready = 0
        for p in probe_ports:
            try:
                with socket.create_connection(("127.0.0.1", p), timeout=0.5):
                    ready += 1
            except OSError:
                pass
        if ready >= target:
            return True
        time.sleep(0.2)
    return False


def kill_proc(proc: Optional[subprocess.Popen]) -> None:
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


def xray_version() -> str:
    try:
        proc = subprocess.run([_xray_path(), "version"], capture_output=True, timeout=20)
        return (proc.stdout or b"").decode(errors="ignore").splitlines()[0]
    except Exception:  # noqa: BLE001
        return "unknown"


# ---------------------------------------------------------------- 配置构造

def build_batch_config(batch: List[NodeTuple], ports: List[int]
                       ) -> Tuple[Optional[Dict[str, Any]], List[Tuple[NodeTuple, int]]]:
    """一个 Xray 实例承载整批节点，返回 (config, [(item, socks_port), ...])

    内核不支持的协议/传输层（QUIC、mKCP、内核级 hysteria2）会被直接跳过，
    它们若进入配置会导致整批启动失败。它们仍会被导出给 Clash / sing-box。
    """
    inbounds: List[Dict[str, Any]] = []
    outbounds: List[Dict[str, Any]] = []
    rules: List[Dict[str, Any]] = []
    pairs: List[Tuple[NodeTuple, int]] = []

    for idx, (item, socks_port) in enumerate(zip(batch, ports)):
        outbound, _, _, _ = parse_node(item[0])
        if not outbound:
            record_drop("batch_config_parse_failed")
            continue
        if not is_kernel_probeable(outbound):
            record_drop(kernel_incompatibility(outbound))
            continue
        in_tag, out_tag = f"in-{idx}", f"out-{idx}"
        inbounds.append({
            "tag": in_tag, "port": socks_port, "listen": "127.0.0.1",
            "protocol": "socks", "settings": {"udp": True, "auth": "noauth"},
        })
        ob = strip_private_keys(outbound)
        ob["tag"] = out_tag
        outbounds.append(ob)
        rules.append({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag})
        pairs.append((item, socks_port))

    if not outbounds:
        return None, []
    outbounds.append({"tag": "direct", "protocol": "freedom"})
    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
    return cfg, pairs


def validate_config(config_dict: Dict[str, Any], path: str) -> bool:
    """用 xray -test 静态校验配置，不合法直接返回 False（比启动失败快且不占端口）

    只写文件、**不删除** —— 调用方往往紧接着要用同一份文件启动内核。
    清理由调用方负责（probe_batch / probe_single_node 的 finally 块）。
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config_dict, f)
    try:
        proc = subprocess.run([_xray_path(), "run", "-test", "-c", os.path.abspath(path)],
                              capture_output=True, timeout=60)
        return proc.returncode == 0
    except FileNotFoundError:
        # 内核不可用时无法校验，退回旧行为（由启动后轮询端口兜底判定）
        return True
    except Exception as exc:  # noqa: BLE001
        log.debug("配置校验异常: %s", exc)
        return True


# ---------------------------------------------------------------- 探测执行

def probe_via_socks(item: NodeTuple, socks_port: int) -> Optional[AliveNode]:
    """经指定 socks 端口完成真实 HTTPS 握手并获取落地 IP"""
    raw_node, server, port, proto = item
    proxies = {
        "http": f"socks5h://127.0.0.1:{socks_port}",
        "https": f"socks5h://127.0.0.1:{socks_port}",
    }
    delays: List[int] = []
    for attempt in range(config.PROBE_REPEAT):
        try:
            start = time.time()
            resp = requests.get(config.PROBE_TEST_URL, proxies=proxies,
                                timeout=config.PROBE_TIMEOUT)
            if resp.status_code not in (200, 204):
                record_drop(f"probe_unexpected_status:{resp.status_code}")
                return None
            delays.append(int((time.time() - start) * 1000))
        except Exception as exc:  # noqa: BLE001
            record_drop(f"probe_failed:{type(exc).__name__}")
            return None

    delay_ms = sorted(delays)[len(delays) // 2]  # 多次探测取中位数更稳
    if not (config.MIN_DELAY_MS < delay_ms < config.MAX_DELAY_MS):
        record_drop("probe_delay_out_of_range")
        return None

    exit_ip: Optional[str] = None
    is_confirmed_exit = False
    for check_url in config.EXIT_IP_URLS:
        try:
            ip_resp = requests.get(check_url, proxies=proxies, timeout=config.EXIT_IP_TIMEOUT)
            if ip_resp.status_code == 200:
                fetched = ip_resp.json().get("ip")
                if fetched:
                    exit_ip = fetched
                    is_confirmed_exit = True
                    break
        except Exception:  # noqa: BLE001
            continue

    # 拿不到穿透落地 IP 时只作普通节点出库，绝不打真出口标签
    if not exit_ip:
        record_drop("probe_no_confirmed_exit_ip")
        try:
            exit_ip = socket.gethostbyname(server)
        except Exception:  # noqa: BLE001
            exit_ip = server

    return (raw_node, server, port, proto, exit_ip, delay_ms, is_confirmed_exit)


def probe_batch(batch: List[NodeTuple], depth: int = 0) -> Optional[List[AliveNode]]:
    """整批节点共用一个 Xray 实例。

    返回 None 表示内核整体不可用（交由调用方回退单节点模式）；
    返回 [] 表示配置非法且已把坏节点全部隔离。
    """
    if not batch:
        return []

    cfg_path = temp_config_path("xray_batch")
    try:
        config_dict, pairs = build_batch_config(batch, allocate_ports(len(batch)))
        if not pairs:
            return []
        if not validate_config(config_dict, cfg_path):
            record_drop("batch_config_invalid", count=len(pairs))
            log.warning("批次配置未通过 xray -test 校验，切换为二分隔离模式")
            return _probe_with_isolation(batch)

        proc = subprocess.Popen([_xray_path(), "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            ports = [p for _, p in pairs]
            # 端口未就绪时不要直接丢弃整批：先给更长的启动窗口（大批量 inbound
            # 在 2 核 runner 上启动明显偏慢），仍不行则拆成小批重试，
            # 否则一批 200 个里 190 个没起来就等于全白跑。
            if not wait_ports_ready(ports, deadline_sec=config.PORT_READY_TIMEOUT):
                record_drop("batch_ports_slow_start", count=len(pairs))
                if depth >= 6:
                    record_drop("batch_ports_not_ready", count=len(pairs))
                    return _probe_serial(batch)
                log.debug("批次端口未在 %.1fs 内就绪，拆小批重试", config.PORT_READY_TIMEOUT)
                return _probe_in_smaller_batches(batch, depth + 1)

            alive: List[AliveNode] = []
            with ThreadPoolExecutor(max_workers=config.PROBE_WORKERS) as executor:
                futures = {executor.submit(probe_via_socks, item, port): item
                           for item, port in pairs}
                for future in as_completed(futures):
                    res = future.result()
                    if res:
                        alive.append(res)
            return alive
        finally:
            kill_proc(proc)
    finally:
        _try_remove(cfg_path)


def _probe_in_smaller_batches(batch: List[NodeTuple], depth: int = 0) -> List[AliveNode]:
    """大批量 inbound 起不来时逐级拆批重试（200 -> 100 -> 50 -> ...）

    内核对同时监听的端口数有上限，超出时会静默部分失败。拆批后每批更小，
    起得来就测、测完即退；若拆到最小批次或递归过深仍起不来，才退化为逐节点测活，
    保证任何情况下都不整批丢弃节点。
    """
    if len(batch) <= config.MIN_BATCH_SIZE or depth >= 8:
        record_drop("batch_ports_not_ready", count=len(batch))
        return _probe_serial(batch)
    mid = len(batch) // 2
    log.info("拆批重试：%d -> %d + %d", len(batch), mid, len(batch) - mid)
    alive: List[AliveNode] = []
    for part in (batch[:mid], batch[mid:]):
        result = probe_batch(part, depth + 1)
        if result is None:
            alive.extend(_probe_serial(part))
        else:
            alive.extend(result)
    return alive


def _probe_with_isolation(batch: List[NodeTuple], depth: int = 0) -> List[AliveNode]:
    """二分隔离：把非法配置拆成两半分别重试，坏节点被逐个剔除而非整批丢弃。

    深度上限 10 层，理论上 8000 节点也只需 ~13 次拆分即可定位到单个畸形节点。
    """
    if len(batch) == 1:
        record_drop("batch_isolated_bad_node")
        log.debug("已隔离单个非法节点: %s", batch[0][1])
        return []
    if depth >= 10:
        record_drop("batch_isolation_depth_exceeded", count=len(batch))
        return []

    mid = len(batch) // 2
    left, right = batch[:mid], batch[mid:]
    results: List[AliveNode] = []
    for part in (left, right):
        cfg, pairs = build_batch_config(part, allocate_ports(len(part)))
        if not pairs:
            continue
        cfg_path = temp_config_path("xray_iso")
        ok = validate_config(cfg, cfg_path)
        _try_remove(cfg_path)  # 这里只做校验，不启动内核，可立即清理
        if ok:
            res = probe_batch(part)
            if res is None:
                # 内核不可用（非配置问题），退化为逐节点，避免整批丢失
                results.extend(_probe_serial(part))
            else:
                results.extend(res)
        else:
            results.extend(_probe_with_isolation(part, depth + 1))
    return results


def _probe_serial(batch: List[NodeTuple]) -> List[AliveNode]:
    alive: List[AliveNode] = []
    with ThreadPoolExecutor(max_workers=config.PROBE_WORKERS) as executor:
        for res in executor.map(probe_single_node, batch):
            if res:
                alive.append(res)
    return alive


def probe_single_node(node_tuple: NodeTuple) -> Optional[AliveNode]:
    """单节点独立实例测活（批量模式的兜底路径）"""
    raw_node, server, port, proto = node_tuple
    outbound, _, _, _ = parse_node(raw_node)
    if not outbound:
        return None
    if not is_kernel_probeable(outbound):
        record_drop(kernel_incompatibility(outbound))
        return None

    socks_port = allocate_ports(1)[0]
    cfg_path = temp_config_path("xray_tmp")
    config_dict = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": socks_port, "listen": "127.0.0.1",
                      "protocol": "socks", "settings": {"udp": True, "auth": "noauth"}}],
        "outbounds": [strip_private_keys(outbound)],
    }
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(config_dict, f)

    proc = subprocess.Popen([_xray_path(), "run", "-c", cfg_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_ports_ready([socks_port]):
            return None
        return probe_via_socks(node_tuple, socks_port)
    finally:
        kill_proc(proc)
        _try_remove(cfg_path)


def _try_remove(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


# ---------------------------------------------------------------- 批次调度

def run_probe(candidates: List[NodeTuple]) -> List[AliveNode]:
    """按批调度测活，受批次大小、并发数、全局时间预算与候选上限约束"""
    log.info("启动 Xray 真实双向通道测活，候选 %d 个"
             "（每批 %d 个共用一个内核，并发 %d）",
             len(candidates), config.PROBE_BATCH_SIZE, config.PROBE_WORKERS)
    log.info("内核版本: %s", xray_version())

    if config.MAX_CANDIDATES and len(candidates) > config.MAX_CANDIDATES:
        log.warning("候选数超过上限，本轮仅测活前 %d 个（共 %d 个）",
                    config.MAX_CANDIDATES, len(candidates))
        candidates = candidates[:config.MAX_CANDIDATES]

    alive: List[AliveNode] = []
    start = time.time()
    total_batches = max(1, (len(candidates) + config.PROBE_BATCH_SIZE - 1) // config.PROBE_BATCH_SIZE)

    for idx, offset in enumerate(range(0, len(candidates), config.PROBE_BATCH_SIZE), 1):
        if time.time() - start > config.TOTAL_BUDGET_SEC:
            log.warning("已达测活时间预算 %ds，剩余 %d 个节点本轮跳过",
                        config.TOTAL_BUDGET_SEC, len(candidates) - offset)
            break

        batch = candidates[offset:offset + config.PROBE_BATCH_SIZE]
        result = probe_batch(batch)
        if result is None:
            log.warning("批量内核启动异常，本批次回退单节点模式")
            alive.extend(_probe_serial(batch))
        else:
            alive.extend(result)

        log.info("批次 %d/%d 完成，累计真实通畅 %d 个（用时 %ds）",
                 idx, total_batches, len(alive), int(time.time() - start))

    log.info("测活完成：真实可用落地节点 %d 个（耗时 %ds）", len(alive), int(time.time() - start))
    return alive


# 兼容旧名
run_real_delay_test_xray = run_probe
test_single_node_xray = probe_single_node
_build_batch_config = build_batch_config
_probe_batch = probe_batch
_probe_via_socks = probe_via_socks
_wait_ports_ready = wait_ports_ready
_allocate_ports = allocate_ports
_kill_proc = kill_proc
