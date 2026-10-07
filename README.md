# Edge Defense Gateway（本地请求防护网关）

一套纯本地状态的请求防护网关：用**客户端身份**（`X-Client-Id`，缺省取对端 IP）
模拟客户端来源与信誉，使限流、拦截与恢复在多个入口（HTTP API / 直接调用引擎）下
得到一致且可解释的结论。

## 1. 总体架构

```
请求 RequestContext(client_id, path, method, ...)
        │
        ▼
┌─────────────────────────── DefenseEngine.evaluate ───────────────────────────┐
│ 维度 1 规则匹配 RuleEngine.match                                             │
│   命中 → 拒绝 rule_matched（403），并向信誉系统登记一次 rule_matched 违规     │
│ 维度 2 信誉隔离 ReputationManager.is_blocked                                 │
│   隔离中 → 拒绝 quarantined（403），隔离期一律拒绝、不消耗限流额度           │
│ 维度 3 分档滑动窗口 SlidingWindowRateLimiter.check（原子：判定+登记）        │
│   额度随信誉等级分档；超限 → 拒绝 rate_limited（429）；通过 → 放行 200       │
└──────────────────────────────────────────────────────────────────────────────┘
        │
        ▼
Decision(allowed, reason, detail, rule_id, snapshot)
```

三个维度**与门**串联，任一不通过即拒绝。拒绝原因 `DenyReason` 为稳定字符串枚举，
调用方既能用状态码区分，也能用响应头 `X-Deny-Reason` / `Decision.reason` 精确区分
“规则拦截”和“触发限流”：

| 结果 | reason | HTTP 状态码 |
|---|---|---|
| 放行 | `null` | 200 |
| 命中防护规则 | `rule_matched` | 403 |
| 来源隔离中 | `quarantined` | 403 |
| 超过速率阈值 | `rate_limited` | 429 |

> 设计约定：限流**不**累积信誉（突发不等于恶意）；只有命中规则才累积违规。
> 隔离拒绝放在限流之前，且不登记限流计数。

## 2. 防护规则模型（`gateway/rules.py`）

- 规则 = `rule_id` + `path_prefix`（路径前缀，区分大小写）+ `methods`（空集合表示全部方法）。
- 按注册顺序返回**第一条**命中的规则；`rule_id` 不允许重复，保证原因可追溯到唯一规则。
- **规则不命中绝不拒绝**，正常流量不会被误伤（有对应测试）。

默认规则（`gateway/service.py`）：

| rule_id | 前缀 | 含义 |
|---|---|---|
| `block-admin` | `/admin` | 后台路径探测 |
| `block-env` | `/.env` | 敏感文件探测 |

## 3. 速率模型（`gateway/rate_limiter.py` + 引擎分档）

- 基于身份的滑动窗口：每个 `client_id` 一个时间戳列表，窗口默认 `1s`。
- `check()` 在同一把锁内完成「淘汰过期 → 比较阈值 → 追加登记」，
  并发请求计数**不丢失、不重复**（1000 并发 / 阈值 500 的测试严格验证）。
- 边界确定：窗口采用左开（边界时间戳过期），第 `limit` 次请求放行、第 `limit+1` 次拒绝。
- 窗口过期后时间戳被淘汰，额度自动恢复；不同身份计数完全隔离；
  窗口清空后身份条目即删除，身份表不随运行时间无限膨胀。

### 3.1 按信誉等级分档的额度

限流额度不再是所有身份一套死阈值，而是跟着实时信誉等级走：
**信誉越差，允许的速率越低**；隔离身份在限流之前已被整体拒绝，不占任何额度。

| 信誉等级 | 默认额度（`limit=10` 时） | 说明 |
|---|---|---|
| `normal` | 10（= `limit`，与旧行为一致） | 正常身份不受影响 |
| `suspect` | 5（`limit/2`） | 1 次违规后下一请求即生效 |
| `restricted` | 2（`limit/4`，至少 1） | 观察期内收紧 |
| `quarantined` | —（整体拒绝，不消耗额度） | 同旧行为 |

- 配置入口：`build_engine(..., level_limits={ReputationLevel.SUSPECT: 3, ...})`
  或直接给 `DefenseEngine` 传 `level_limits`。未配置的等级回退到 `limit`；
  `DefenseEngine` 缺省（None）时所有等级共用 `limit`，与旧行为完全一致。
- 默认分档由 `gateway/service.py: default_level_limits()` 给出：
  `normal=limit`、`suspect=max(1, limit//2)`、`restricted=max(1, limit//4)`。
- **等级一变，下一次请求立即按新额度判定**（每次判定都实时取等级）。
- 每次判定的响应快照里可见本次所用档位与剩余额度：
  `snapshot.rate_limit = {tier_level, limit, used, remaining, ...}`。
- 对老行为的影响：**normal 身份额度与之前完全一致**；只有产生了违规记录
  （suspect/restricted）的身份会被收紧，这正是本特性的目的。

## 4. 信誉、隔离与恢复模型（`gateway/reputation.py`）

### 4.1 连续违规逐级升级

| 连续违规次数 | 等级 |
|---|---|
| 0 | `normal` |
| 1 | `suspect`（可疑） |
| 2 | `restricted`（限制） |
| ≥3 | `quarantined`（隔离） |

### 4.2 隔离（指数退避）

进入隔离时 `quarantine_count += 1`，隔离时长：

```
duration = min(300s, base_quarantine_seconds × 2^(quarantine_count - 1))
```

默认 `base=10s`，即第 1 次隔离 10s、第 2 次 20s、第 3 次 40s……封顶 300s。
隔离期内**所有请求一律拒绝**（即使路径正常），原因恒为 `quarantined`。

### 4.3 隔离到期后的逐级恢复

状态推进是**时间驱动**的（任何一次查询/请求都会惰性推进，无需后台线程）：

```
quarantined ──到期──▶ restricted ──5s 无违规──▶ suspect ──5s 无违规──▶ normal
```

- 隔离到期先降为 `restricted` **观察期**，请求恢复放行（仍受规则与限流约束）。
- 每经过一个 `recover_step_seconds`（默认 5s）且期间无新违规，才再降一级。
- 观察期内再次违规：连续计数继续累加，立即重新隔离，且 `quarantine_count` 增加、
  隔离时长翻倍。

### 4.4 表现良好加速恢复（恢复进度）

加速进度有两个**独立**来源，阈值同为 `good_accel_steps`
（默认 **2**，`ReputationManager` / `build_engine` 可配）：

- **时间驱动**：每完成一个无违规恢复步（`recover_step_seconds`，默认 5s），
  `recovery_progress + 1`；达标时**立即跳回 `normal`**（跳级兑现，进度归零），
  事件记为 `accelerated_recover`。例：`good_accel_steps=1` 时，隔离到期后
  第一个干净步就直接回 `normal`，跳过 `suspect`。
- **请求驱动**：隔离后**观察恢复期**内（`in_recovery` 的 `restricted`/`suspect`），
  每一次**被放行**的请求（引擎放行路径调用 `record_good`）`good_progress + 1`；
  达标时**立即降一级**（`restricted→suspect→normal`，进度归零）。

因此观察期内持续表现良好的身份**明显快于**“不再出现、只按时间熬”的身份：
默认配置下活跃身份 4 次放行即回 `normal`（每 2 次降一级），静默身份要熬
两个恢复步（10s）。未进入观察期的身份（如只有 1 次违规的 `suspect`）不受
请求驱动加速影响，行为与旧版本一致。

- 默认阈值 2 下，**时间驱动**的恢复节奏与旧阶梯完全一致
  （restricted→suspect→normal 各一步）。
- **再违规即回退**：两项进度都清零（违规事件带 `recovery_progress_cleared` /
  `good_progress_cleared` 字段），连续违规计数累加，该重新隔离就重新隔离。
- 进度随状态 JSON 一起持久化，且进度变化即落盘：进程重启后**不白攒**
  （进度还在）、**不重攒**（同一恢复步/同一请求不会重复累计）。
- 读路径（`get_level` / `is_blocked` / `snapshot`）**不累计**放行进度，
  同一次请求经过多个调用点也不会被算重；并发请求由同一把锁串行化，
  每个放行请求恰好累计一次（均有测试覆盖）。

### 4.5 状态回收与保留边界

长时间运行不会让状态无限膨胀——回收是**真删除**，不是打标记：

- **闲置回收**：等级为 `normal` 且超过 `gc_idle_seconds`（默认 **3600s**）未出现的
  身份会被**从活动状态表中删除**，只把影响后续结论的最小信息
  （`quarantine_count`、`last_seen`）移入独立的**归档表**；该身份的事件流水一并清除。
- **归档表有界**：归档记录超过 `gc_archive_seconds`（默认 **7 天**）未再出现即
  彻底过期；条数超过 `gc_archive_max_entries`（默认 **10000**）时淘汰最旧。
  因此活动状态与归档记录的规模都**不随见过的身份数无限增长**。
- **绝不回收**：隔离中、观察恢复期（`restricted`/`suspect`）、最近有活动的身份。
  回收前会先按当前时间推进状态机，确保判定基于最新状态。
- **结论可复现**：归档记录随状态一起落盘；被回收身份再次出现时从归档表原地
  复活，由于 `quarantine_count` 保留，再次隔离的退避次数/时长与从未回收完全
  一致（不会退化成“从没见过”的首次隔离）——重启后同样成立。只有归档记录
  本身过期（默认 7 天未再出现）后，才按“第一次见”处理。
- **事件保留边界**：每个身份的事件流水最多保留 `max_events_per_client`
  （默认 **100**）条，超出丢弃最旧。
- **触发方式**：`ReputationManager.gc(now)` 可显式调用；请求路径上也会按
  `gc_interval_seconds`（默认 **60s**）自动触发。`build_engine` 透传
  `gc_idle_seconds` / `gc_archive_seconds` / `gc_archive_max_entries` /
  `max_events_per_client` / `good_accel_steps`。
- 回收不影响已成立的判定结论：等级、隔离退避次数、恢复进度语义均保持不变。

### 4.6 持久化与可追溯

- 活动状态、归档表与事件流水以 JSON 原子写入 `data/reputation.json`
  （临时文件 + `os.replace`）。
- 进程重启后 `load()` 完整复现等级、隔离截止时间、隔离次数、两项恢复进度、
  观察期标记与归档表（有重启复现测试）；旧格式状态文件中的“归档”条目
  会在加载时自动迁入归档表，结论不变。
- 每次变更（`violation / escalate / quarantined / quarantine_released / recover /
  accelerated_recover / gc`）都追加一条事件，形成审计轨迹，可通过
  `ReputationManager.events(client_id)` 查询。

## 5. 可解释性与日志

- 每次判定都通过 `logging` 打印：客户端、路径、原因（ALLOW/DENY）、规则 ID、
  以及包含限流窗口与信誉状态的**状态快照**。
- `Decision.snapshot`（以及 HTTP 响应体中的 `snapshot` 字段）包含：
  - `rate_limit`：本次档位（`tier_level`）、该档阈值、窗口、已用、剩余、窗口内时间戳；
  - `reputation`：等级、连续违规数、隔离次数、隔离截止与剩余时间、
    时间驱动恢复进度（`recovery_progress`）、请求驱动放行进度（`good_progress`）、
    是否处于观察恢复期（`in_recovery`）。

## 6. 运行与验证

```bash
# 安装依赖（需 uv）
uv sync

# 启动服务
uv run uvicorn main:app --reload

# 示例：正常请求
curl -s -H 'X-Client-Id: alice' http://127.0.0.1:8000/gateway/home | jq

# 示例：命中规则（连续 3 次后该身份进入隔离）
for i in 1 2 3; do
  curl -s -i -H 'X-Client-Id: scanner' http://127.0.0.1:8000/gateway/admin | grep -i 'x-deny-reason'
done

# 示例：触发限流（原因与规则拦截可区分：429 + rate_limited）
for i in $(seq 1 12); do
  curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Client-Id: burst' http://127.0.0.1:8000/gateway/home
done
```

运行测试（含并发、阈值边界、隔离恢复、加速恢复、回收边界、重启复现、
正常流量不误伤；日志中会打印每条用例的场景结论与关键状态快照）：

```bash
uv run pytest -q                                  # 静默概要
uv run pytest -o log_cli=true -o log_level=INFO   # 查看每条用例的场景、结论与状态快照
uv run pytest tests/test_engine.py                # 仅编排层测试
uv run pytest tests/test_tiered_rate_limit.py tests/test_recovery_progress.py tests/test_gc.py
```

本地手工验证新能力（默认装配：normal=10/s、suspect=5/s、restricted=2/s）：

```bash
# 分档限流：先违规 1 次（403 rule_matched），再连续打正常路径，
# 第 6 次起 429，且响应 snapshot.rate_limit.tier_level == "suspect"、limit == 5
curl -s -H 'X-Client-Id: tiered' http://127.0.0.1:8000/gateway/admin > /dev/null
for i in $(seq 1 7); do
  curl -s -H 'X-Client-Id: tiered' http://127.0.0.1:8000/gateway/home | jq -c '.snapshot.rate_limit | {tier_level, limit, remaining}'
done

# 表现良好加速恢复：先违规 3 次进入隔离（10s），等隔离到期后连续打正常路径，
# 观察 snapshot.reputation：good_progress 逐次累计，每 2 次放行降一级，
# 第 4 次放行即回到 normal（只按时间熬需要 10s 以上）
for i in 1 2 3; do curl -s -H 'X-Client-Id: recover' http://127.0.0.1:8000/gateway/admin > /dev/null; done
sleep 10
for i in 1 2 3 4; do
  curl -s -H 'X-Client-Id: recover' http://127.0.0.1:8000/gateway/home | jq -c '.snapshot.reputation | {level, good_progress, in_recovery}'
done

# 状态回收：默认 gc_idle_seconds=3600 不便手测，可用小参数本地起进程验证——
# 身份被真正移出活动状态表（gc 返回的 states 计数下降），归档记录有界
uv run python - <<'PY'
from gateway.reputation import ReputationManager
mgr = ReputationManager(gc_idle_seconds=5.0, gc_archive_max_entries=3)
for i in range(10):
    mgr.get_level(f"one-off-{i}", 0.0)   # 10 个一次性身份
print(mgr.gc(100.0))                     # states=0、archived<=3：规模有界
PY
```

### 对老行为的影响

- **正常（normal）身份**：限流额度、判定结果与旧版本完全一致；`record_good`
  对 normal 身份是零效果操作。
- **未进观察期的违规身份**（suspect/restricted 但未被隔离过）：不享受请求驱动
  加速，恢复节奏与旧版本一致。
- **观察期身份**：时间驱动的逐级恢复节奏不变；新增的请求驱动加速只会让
  持续放行的身份**更快**恢复，不会更慢。
- **回收**：保护名单（隔离中/观察期/最近活跃）不变；变化在于闲置身份被
  **真正移出内存**（旧版本只打归档标记、条目永久残留），前科结论在归档
  保留期（默认 7 天）内与旧版本一致，超期后才按“第一次见”处理。
- **旧状态文件**：加载时自动把旧格式中的“归档”条目迁入归档表，结论不变。

### 测试覆盖一览

| 测试文件 | 覆盖内容 |
|---|---|
| `tests/test_rules.py` | 规则命中/不命中、方法限定、重复 rule_id |
| `tests/test_rate_limiter.py` | 阈值边界、窗口恢复、并发精确计数、身份隔离 |
| `tests/test_reputation.py` | 逐级升级、隔离拒绝、到期逐级恢复、观察期再犯加倍、重启复现、事件追溯 |
| `tests/test_tiered_rate_limit.py` | 分档默认值（normal 不变）、等级变化即时生效、分档阈值边界、隔离不占额度、并发分档精确计数、快照可见档位 |
| `tests/test_recovery_progress.py` | 加速恢复跳级、默认节奏与旧行为一致、请求驱动加速（活跃明显快于静默）、再违规清零回退并重新隔离、进度重启复现（不白攒/不重攒）、并发只累计一次、读路径不计进度、引擎联动 |
| `tests/test_gc.py` | 闲置真回收（状态表收缩）、隔离/观察期/活跃身份不回收、归档后结论重启复现、归档记录过期与条数上限、规模有界、归档身份复活、事件保留边界、自动回收触发 |
| `tests/test_engine.py` | 三维度联合判定、原因可区分、正常流量不误伤、隔离不占限流额度、200 并发不变量 |
| `tests/test_http.py` | 200/403/429 状态码与 `X-Deny-Reason` 头、响应内快照 |

## 7. 代码结构

```
gateway/
  models.py         # RequestContext / Rule / Decision / 原因与等级枚举
  rules.py          # 维度一：规则匹配
  reputation.py     # 维度二：信誉累积、隔离、退避恢复、双驱动加速进度、闲置真回收与有界归档、JSON 持久化
  rate_limiter.py   # 维度三：线程安全滑动窗口（支持按次分档额度）
  engine.py         # 三维度编排、按等级分档限流、判定日志
  service.py        # 默认规则/分档阈值/恢复与回收参数的装配
main.py             # FastAPI 入口（create_app 工厂，多入口共用同一引擎）
tests/              # 全部单元与集成测试
data/reputation.json# 运行期信誉状态（已 gitignore）
```
