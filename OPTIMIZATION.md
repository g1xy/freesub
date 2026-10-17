# freesub 项目优化建议报告

> 分析对象：`scripts/main.py`（996 行单文件）、`.github/workflows/update.yml`、`scripts/requirements.txt`、`.gitignore`
> 结论：核心链路设计（真实 Xray 隧道测活 + ASN 家宽甄别）思路是对的，但存在 **3 个会导致产物错误/资产大量丢失的致命缺陷**，以及一批性能与健壮性隐患。

---

## 🔴 P0 致命缺陷（必须优先修复）

> ✅ **状态：已于 2026-09-19 全部修复**（改动在 `scripts/main.py`），并新增 `scripts/test_parse.py` 六项回归测试覆盖这 4 个坑，workflow 已插入测试步骤。以下保留原始分析作为背景。

### 1. 所有 trojan 节点被静默丢弃 —— `main.py:442`
`convert_to_clash_dict()` 的 trojan 分支引用了变量 `stream`，但该变量只在 vless 分支内定义。trojan 分支走到 `stream.get(...)` 时抛 `NameError`，被外层 `except Exception: pass` 吞掉，返回 `None`，节点在 `classify_and_filter()` 阶段被丢弃。

**实测证据**（用真 trojan 链接调用）：
```
trojan://pw@1.2.3.4:443?sni=e.com#t  ->  convert_to_clash_dict(...) 返回 None
```
代价很大：这些节点**已经通过了 Xray 真实测活**（花掉了全部测活开销），却在最后转换环节白丢。而 trojan 在公开源里占比通常不低。

修复：在 trojan 分支补 `stream = outbound["streamSettings"]`。

### 2. `singbox.json` 是坏配置 —— `main.py:702-712`
生成的 outbounds 只有 `selector / urltest / direct / block` 四组，**从未把节点本身转成 sing-box outbound 加进去**，而 selector/urltest 却引用了这些不存在的 tag。

**实测产物片段**：
```json
{"type":"selector","tag":"select","outbounds":["auto","node-A","node-B"]}
```
`node-A` / `node-B` 在整个文件里没有任何定义 → 客户端加载即报错，README 里所有 sing-box 链接当前都是无效的。

修复：新增 `clash_proxy → sing-box outbound` 转换器（vless/vmess/trojan/ss/hysteria2 各一套），再拼进 outbounds，并补齐 `inbounds` / `route` 段。

### 3. hysteria2 抓了但从不测活 —— `main.py:474`
`test_single_node_xray()` 开头直接 `if proto == "hysteria2": return None`。而 `SOURCE_URLS` 里专门有一个 hysteria 源（`10ium/telegram-configs-collector/.../hysteria`），抓下来的节点 100% 作废。Xray-core 从 v1.8.x 起已支持 hysteria2 outbound（当前固定的 v1.8.24 也支持）。

修复：删除该跳过分支，用 hy2 outbound 正常测活（注意放行 UDP）；或换成 sing-box 内核统一测活。

### 4. README Worker 示例链接被 Markdown 套娃 —— `main.py:882`（已知问题）
```js
const ghUrl = "[https://raw.githubusercontent.com/](https://raw.githubusercontent.com/)" + OWNER + ...
```
写进 JS 代码里的其实是 Markdown 链接语法，部署后必然 404/语法错。改成纯字符串 `"https://raw.githubusercontent.com/"`。
同时该示例要求把 GitHub **PAT 明文硬编码**在 Worker 源码里，建议改为 Worker 环境变量/Secrets 读取。

---

## 🟠 P1 性能与资源浪费

> ✅ **状态：已于 2026-09-19 全部实施**（`scripts/main.py`）。关键改动：① 单 Xray 实例多 inbound 批量测活（保留原单节点模式作为内核异常时的兜底路径）；② 跨源按链接核心归一化去重；③ 抓源并发 + 重试；④ 解析结果缓存；⑤ maxminddb 按线程隔离；⑥ 全局时间预算与候选上限。

| # | 问题 | 位置 | 建议 |
|---|------|------|------|
| 5 | **每测一个节点就 fork 一个 Xray 进程 + 写一份临时配置 + `sleep(0.35)`**。25 并发 = 25 个进程同时驻留，GitHub 2 核 runner 上进程创建/销毁开销远超实际测活开销，且固定 sleep 不可靠（启动慢则假阴性） | `471-548` | 改为**单 Xray 实例多 inbound**：每节点一个 socks inbound（随机端口）+ routing rule 按 `inboundTag` 绑定对应 outbound，一次启动测完全部节点；或至少改为进程池复用 + 轮询端口就绪替代 sleep |
| 6 | **同一节点被重复解析 3 次**（候选筛选、测活、分类各一次） | `987 / 473 / 636` | 解析结果缓存到 dict，全链路只解析一次 |
| 7 | **跨源重复节点未去重**：`extract_nodes_from_text` 保留完整 link（含 `#备注`），同一节点在不同源备注不同 → 被视为两个候选，白白重复测活 | `181-198` | 提取阶段按 `link.split("#")[0]` 归一化去重，预计可减少 30%~60% 测活量 |
| 8 | **抓源是串行 requests**，10 个源 × 25s 超时，最坏 250s | `208-218` | `ThreadPoolExecutor` 并发抓取 + `HTTPAdapter(max_retries=3)` |
| 9 | **maxminddb Reader 跨 30 个线程共享**，`Reader.get()` 内部会 seek 文件句柄，非线程安全，并发下数据错乱风险 | `604-605 / 652` | 每个线程独立 `open_database`（thread-local），或加读锁 |
| 10 | `get_rdns_host()` 里 `socket.setdefaulttimeout(1.2)` 是**全局副作用**，在线程池里改全局 socket 状态 | `582` | 用 `socket.create_connection` 显式超时，或改用 dnspython 并设置每线程超时 |
| 11 | **无全局时间预算**：节点池上万时，最坏 10000/25 × 7s ≈ 47 分钟，逼近 Actions 上限 | 全局 | 加 deadline（如 35 分钟）+ 候选上限（随机采样/按历史延迟排序优先测） |
| 12 | 延迟只测 1 次，且下限 `30ms` 会误杀优质低延迟节点；无带宽测速 | `511-514` | 取 2~3 次中位数；下限放宽到 10ms；可选加分档测速 |

## 🟡 P2 健壮性与 CI

> ✅ **状态：13~20 项已于 2026-09-19 / 2026-10-15 全部实施**（详见文末「实施记录」）。P3 亦已全部完成并重构为 `freesub/` 包。

| # | 问题 | 建议 |
|---|------|------|
| 13 | **无"空结果保护"**：若所有源同时挂掉，`alive=0`，脚本仍会写出空订阅并 push，**线上订阅被清零** | 存活数 < 上次结果的 50%（或 < N）时直接中止、保留上一版并报警 |
| 14 | workflow 无 `concurrency`、无 `timeout-minutes`，多次运行并发 push 会冲突 | 加 `concurrency: group: update-sub, cancel-in-progress: true`；`timeout-minutes: 45`；push 前 `git pull --rebase` + 重试 |
| 15 | `.gitignore` 漏了 `xray` / `xray.zip` / `xray_tmp_*.json`（30MB 二进制 + 残留临时文件风险） | 补齐忽略项 |
| 16 | mmdb 与 xray 每次全量下载（~40MB），无缓存、无版本更新 | 用 `actions/cache` + mmdb 本地超过 30 天重下；xray 改为拉取 latest release 而非硬编码 v1.8.24 |
| 17 | 节点源健康度无追踪，失效源长期占位 | 记录 `output/sources_status.json`（成功率/连续失败次数），连续失败 N 次降权或告警 |
| 18 | `VALID_SS_CIPHERS` 定义了却从未使用（死代码）；ss 的 `plugin`（obfs/v2ray-plugin）被忽略，这类节点入库也连不上 | 用白名单过滤不支持的 cipher；解析 plugin 或提前丢弃带 plugin 的节点 |
| 19 | vless/vmess 只支持 ws，**grpc / httpupgrade / xhttp / quic 全部缺失 streamSettings** → 全部测活失败被浪费 | 补全各 network 的 settings，或提前识别并跳过 |
| 20 | 无元信息输出，无法监控迭代质量 | 输出 `output/meta.json`：更新时间、总数、协议分布、国家分布、测活耗时 |

## 🟢 P3 工程质量

- **单文件 996 行** → 拆为 `fetch / parse / probe / classify / export` 五个模块，便于测试与复用。
- 大量 `except Exception: pass` 吞异常 → 引入 `logging` + `--debug` 开关，把丢弃原因（parse 失败/不支持协议/超时）计数后打印。
- 模块级 `ensure_directories()` 在 import 时就建目录（副作用）→ 移入 `main()`。
- 无 CLI 参数、无类型标注、无单元测试 → 至少给 `parse` 和 `convert` 补一套用例（本次 3 个 P0 全都能被 2 行测试拦住）。
- `requirements.txt` 里 `PySocks` 未被使用；可考虑 `httpx` 替代 `requests` 提升并发效率。
- 路径硬编码 `./xray`（Linux）→ 按 `sys.platform` 选择内核，方便 Windows 本地调试。
- `README` 里的 `OWNER = "hezhanleiok"` 与 `GITHUB_REPOSITORY` 环境变量不一致 → 统一从环境变量注入。

---

## ✅ 建议执行顺序

| 优先级 | 动作 | 预期收益 |
|:---:|------|---------|
| P0 | 修 trojan `stream` NameError | 直接挽回一整类已测活节点 |
| P0 | 重写 sing-box 导出 | sing-box 订阅从"完全不可用"变为可用 |
| P0 | 放开 hysteria2 测活 | 沉睡的一个源开始产出 |
| P0 | 修 Worker 示例 URL + PAT 改 Secrets | 私有网关方案可用且安全 |
| P1 | 单 Xray 实例多 inbound 测活 | 测活耗时/资源下降一个量级 |
| P1 | 跨源归一化去重 | 减少 30%~60% 无效测活 |
| P1 | 抓源并发 + 解析结果缓存 + mmdb 线程隔离 | 稳定性与耗时双改善 |
| P2 | 空结果保护 + workflow concurrency/timeout | 避免线上订阅被清零 |
| P3 | 模块化 + 日志 + 单测 | 长期可维护 |

> 补充提醒：订阅内容来自第三方公开源，节点运营方可观测经其转发的流量，README 中建议加一句"勿用于传输敏感信息/登录凭据"的免责说明。

---

## ✅ 2026-10-15 实施记录（P2 #16~20 + 全部 P3）

### 重构：单文件 1422 行 → `freesub/` 包
`main.py` 退化为纯 CLI 编排（~200 行），拆分为：

| 模块 | 职责 |
|---|---|
| `config.py` | 可调参数（全部支持环境变量）、源列表、ASN/地理判定表、平台适配 |
| `logutil.py` | logging 封装 + **丢弃原因统一计数**（`record_drop` / `report_drop_stats`） |
| `fetcher.py` | 并发抓源、base64 递归展开、跨源去重、**源健康度持久化** |
| `parse.py` | 链接 → Xray outbound，**全传输层 streamSettings**，解析缓存 |
| `environment.py` | 内核/mmdb 下载、缓存、版本解析 |
| `prober.py` | Xray 真实隧道测活、批量调度、配置校验、二分隔离、拆批重试 |
| `classifier.py` | 出口 IP 甄别与住宅认证 |
| `exporters.py` | Clash / sing-box 转换（与内核配置分离） |
| `reporter.py` | 订阅文件、README、meta.json |

`ensure_directories()` 等 import 期副作用已移入运行时。

### P2 剩余项
- **#16 缓存与版本**：`actions/cache` 复用 xray+mmdb；`_is_fresh()` 按 mtime 判定（缺失即重下）；mmdb 30 天过期；xray 可拉 latest 但**默认锁定 v1.8.24**（见下方兼容性）。
- **#17 源健康度**：`output/sources_status.json` 记录成功/失败次数与连续失败；连续失败 ≥5 的源本轮降权到末尾（但保证至少保留一个可抓源）。
- **#18 ss cipher/plugin**：白名单真正启用；obfs/v2ray-plugin 等内核不支持的插件**在候选阶段就丢弃**并计数，不再白跑测活。
- **#19 传输层**：补全 `ws / grpc / httpupgrade / xhttp / h2 / quic / kcp / tcp-http`，含 Reality、flow(`xtls-rprx-vision`)、`scy`、`spiderX`；Clash 与 sing-box 侧同步映射（已用真实内核逐个验证）。
- **#20 meta.json**：`output/meta.json` 含协议分布、国家分布、家宽分布、延迟分位（p50/p90）、丢弃原因 Top、各阶段耗时、源健康度。

### P3 全部完成
模块化拆分、logging + `--debug`、CLI 参数（`--max-candidates/--workers/--batch-size/--timeout/--budget/--repeat/--sources/--dry-run/--xray`）、类型标注、61 项测试、`sys.platform` 路径适配、`README` owner 改为 `GITHUB_REPOSITORY` → `git remote` → 默认值三级回退。

### 🚨 本轮实测新发现的三个严重问题

**1. Xray-core 26.x 破坏性变更（最严重）**
用真实内核跑 `xray -test` 逐个验证时发现 26.3.27 已移除：
- `allowInsecure`（改为 `pinnedPeerCertSha256`）—— **原代码每个 TLS 配置都带它，升级内核后整批 200 个节点一个都起不来**
- QUIC 传输（建议迁 xhttp H3）
- 内核级 `hysteria2` 协议（`unknown config id: hysteria2`）
- mKCP 的 `header`/`seed`（改为 `finalmask`/`udp`）

处置：内核**默认锁定 v1.8.24**；TLS 改为只写 `serverName`+`alpn`（两代内核均接受）；Reality 同时写 `password` 与 `publicKey`；新增 `is_kernel_probeable()` 把 QUIC/mKCP/内核级 hy2 排除出内核配置（仍正常导出给 Clash/sing-box）；新增 `test_xray_rejects_none_of_our_kernel_configs` 集成测试，用真实二进制守住这条线。

**2. 明文 SIP002 的 ss 链接被误杀**
`ss://aes-256-gcm:pw@host:port` 的 userinfo 是明文，旧代码无条件先 base64decode，得到二进制垃圾并当作 cipher，节点被白名单全部丢弃（丢弃原因里可见 `ywvzlti1ni1ny206...` 这类密文）。修复：先判断是否含 `:`，再尝试 base64；并补 `unquote`（线上大量 userinfo 是 `%3D` 形式）。修复后同类"密文 cipher"从 25 条降到 0。

**3. 端口未就绪导致整批丢弃**
实测 40 个一批时有 **37 个** inbound 没在 8s 内就绪，整批直接返回空列表 —— 好节点被白丢。修复：等待上限提到 20s（可配），仍失败则**逐级拆批重试**（200→100→50→…），拆到最小批次仍失败才逐节点兜底，任何情况下都不整批丢弃。

### 测试规模
从 12 项扩到 **61 项**，其中 1 项为真实 xray 二进制集成测试（无内核时自动 skip）。

---

## 🚀 2026-10-15 Xray-core 26.x 适配升级（已完成）

### 背景
上一轮发现 26.x 与 1.8.x 配置不兼容后，采取了「锁死 1.8.24」的保守策略。本轮按要求**完成对 26.x 的正式适配**，
内核恢复跟随 `latest`。所有能力边界均由**真实二进制 `xray run -test` 逐项实测**得出，不靠推测。

### 26.x 能力矩阵（实测结论）

| 维度 | 支持 | 已移除 |
|---|---|---|
| 协议 | vless / vmess / trojan / shadowsocks / socks / http / freedom / blackhole | 内核级 `hysteria2`（unknown config id）、内核级 `tuic` |
| 传输层 | raw(tcp) / ws / grpc / httpupgrade / xhttp | `http`(h2)、`quic`、`kcp`(mKCP) |
| REALITY | 仅 `raw` / `xhttp` / `grpc` | 配 `ws` / `httpupgrade` 会启动失败 |
| TLS | `serverName` / `alpn` / `pinnedPeerCertChainSha256` / `fingerprint` / `rejectUnknownSni` | `allowInsecure`（→ pinnedPeerCertSha256） |
| ss cipher | `aes-*-gcm` / `chacha20-ietf-poly1305` / `xchacha20-ietf-poly1305` / `none` | `aes-*-ctr` / `aes-*-cfb` / `rc4-md5` / `chacha20-poly1305` / `2022-blake3-*`(需特定密钥长度) |
| REALITY 公钥字段 | `password`（`publicKey` 亦兼容） | — |

### 处置策略：从「整类丢弃」改为「降级 + 分流」

**1. 传输层降级（保住节点）**
QUIC / H2 / mKCP 原先被整类排除，现在改为**内核侧降级为 `raw`**，原值暂存到 `_originalNetwork`：
- 内核能启动 → 这些节点仍可被真实测活（比丢弃好）
- Clash / sing-box 导出时读 `_originalNetwork`，客户端配置依旧正确
- 关键细节：kcp 的 `headerType`（srtp/utp/wechat-video）与 raw 语义完全不同，
  降级时必须清空，否则握手失败 —— 已单独处理并加测试
- kcp 的 `seed` / `serviceName` / `quicSecurity` 等内核用不到的参数暂存到
  `_originalParams`，供 Clash 导出使用

**2. 协议分流（保住 hy2）**
Xray 26.x 已不注册内核级 hysteria2，实测确认（`unknown config id: hysteria2`）。
公开源里 hy2 占约 5%（实测 5540 个去重节点中 270 个），直接丢弃损失一整类协议。

**引入 sing-box 作为补充测活内核**（`freesub/singbox.py` + `freesub/sbprober.py`）：
- sing-box 1.14.3 原生支持 hysteria2，已实测 `check` 通过 + 真实节点 HTTPS 握手成功（status=204，2584ms）
- 架构：Xray 负责绝大多数节点（单实例多入站，高吞吐）；sing-box 只负责 hy2/tuic
- 限制：sing-box 的 inbound 无法像 xray 那样靠 routing 绑多 outbound，故每节点一个实例；
  hy2 占比不高，可接受
- 内核不可用时降级：跳过 hy2，不影响其他协议

**3. ss cipher 收敛**
26.x 已移除的 cipher 在**解析阶段**直接丢弃（连候选都不进），比「解析后再判不可测活」更省。

### 修复的一个隐蔽 bug
`validate_config` 原本在 `finally` 里删除临时配置，但调用方紧接着要用**同一份文件**启动内核。
文件已删 → 内核启动失败 → 端口永不就绪 → 触发无限拆批重试（实测 25→12→6 递归，单批耗时从 ~14s 涨到 184s）。
已改为：`validate_config` 只写不删，清理由调用方 `finally` 负责；新增
`test_probe_batch_launches_with_the_validated_file` 断言校验与启动用的是同一份文件。

### 升级后实测结果
- 全量验证：抓取 5540 节点 → **Xray 30/30 组合通过 `xray run -test`，sing-box 1/1 通过 `check`，0 失败**
- 端到端：候选 3666 → 分流 Xray 3521 / sing-box 145（hysteria2）
- 测试规模：12 → **71 项**，含 Xray 与 sing-box 双内核集成测试

## 🎯 2026-10-17 出库配额（800+ → 40 个）

**需求**：全量发布 800+ 节点对客户端不友好（首连测速慢、列表难翻），
只保留 🇭🇰 香港 / 🇺🇸 美国 / 🇯🇵 日本 / 🇰🇷 韩国 各 10 个，合计 40 个。

**实现**（`freesub/quota.py`，挂在「分类甄别之后、导出之前」）：

```python
COUNTRY_QUOTA = os.environ.get("COUNTRY_QUOTA", "HK:10,US:10,JP:10,KR:10")
```

- 配额外的国家整体不导出，记 `quota_country_excluded:<CC>`
- 超出配额的尾部节点丢弃，记 `quota_overflow:<CC>`
- 挑选顺序：`QUOTA_PREFER_RESIDENTIAL=1`（默认）时**真家宽优先**，同类按延迟升序；
  置 0 则纯按延迟升序
- 输出顺序 = 配额声明顺序 + 组内挑选顺序，全量订阅里编号按地区分段连续（01-10 HK、11-20 US…）
- 某地区本轮凑不满时**有多少给多少**并打 WARNING，不拿其他地区顶替

**踩到的坑：空结果保护会误杀首轮收敛**
原逻辑是 `len(verified) < previous_count * 0.5` 就中止导出。配额把发布量从 820 降到 40 后，
上一版 `previous_count` 仍是 820，第一次跑必被判成「抓取异常」。已改为
`expected = min(previous_count, quota_total())`，并加回归用例
`test_cli_quota_does_not_trip_previous_volume_guard`。

**可观测性**
- `meta.json` 新增 `quota` 字段：`{CC: {target, available, selected, residential}}`
- README 顶部自动生成「🎯 出库配额」说明行（含开关状态与合计上限）
- 日志：`出库配额截断: HK=10/10, US=10/10, … | 合计 40/40（家宽 3）`

**调整方式**
- 环境变量：`COUNTRY_QUOTA="HK:10,US:10,JP:10,KR:10,SG:5"`（GitHub Actions 加 env 即可）
- CLI：`python scripts/main.py --country-quota "JP:20,TW:20"`
- 关闭配额：`COUNTRY_QUOTA=""` 或 `--country-quota ""`（发布全部存活节点）

**实测**（模拟 820 个存活节点：HK 300 / US 200 / JP 150 / KR 80 / TW 60 / SG 30）
`v2ray.txt` / `clash.yaml` / `singbox.json` 三端均 40 个，`by-country` 只剩 HK/JP/KR/US 四个目录，
家宽池 10 个随配额一并收敛；测试规模 77 → **83 项**。
