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

### 4.4 表现良好加速恢复（按“表现”而不只是熬时间）

观察恢复期内，恢复推进有两条并行通道，**谁先到谁触发**，但每个恢复步只兑现一次：

1. **时间通道（旧行为，不变）**：在当前等级熬满 `recover_step_seconds`（默认 **5s**）
   且无新违规，即完成一个恢复步。从不回来的身份也能靠时间慢慢恢复。
2. **良好行为通道（新增，真正按表现加速）**：在当前等级**持续表现良好满
   `0.4 × recover_step_seconds`（默认 2s）** 之后，每来一个**被放行的良好请求**
   攒 1 点 `good_credit`；攒满 `good_requests_per_step`（默认 **3**）点即提前
   完成一个恢复步，事件记为 `recover`（带 `via="good_behavior"`，时间通道为
   `via="time"`）。

- 默认参数下对比：隔离到期进入 `restricted` 后（t=12）：
  - 持续正常发请求：t≈15 降 `suspect`、t≈18 回 `normal`，观察期约 **4~6s**；
  - 干脆再也不来：t=17 才降 `suspect`、t=22 才回 `normal`，观察期 **10s**。
  - “一直正常发请求”明显比“只熬时间”更快脱身，默认配置下即可观测到差异。
- **为什么要 2s 最短持续时间**：如果只数请求次数，同一时刻刷一堆请求就能瞬间
  跳过观察期，等于可以被刷量绕过。加上“必须在当前等级持续表现满 2s”后，
  瞬时刷量最多推进一个恢复步，无法直接从 `restricted` 跳回 `normal`。
- 每完成一个无违规恢复步 `recovery_progress + 1`；达到 `good_accel_steps`
  （默认 **2**）时**立即跳回 `normal`**（跳级兑现，进度归零），事件记为
  `accelerated_recover`。
- 只有**真正放行**的请求才计良好：规则命中（`rule_matched`）、隔离拒绝
  （`quarantined`）、限流拒绝（`rate_limited`）都不计。
- **再违规即回退**：`good_credit` 与 `recovery_progress` 立即清零（违规事件带
  `good_credit_cleared` / `recovery_progress_cleared` 字段），连续违规计数累加，
  该重新隔离就重新隔离、退避时长照常翻倍。
- `good_credit` 与 `recovery_progress` 都随状态 JSON 持久化，且累计/迁移即落盘：
  重启后**不白攒**（攒了几点还在）、**不重攒**（同一步不会重复累计）；所有更新
  都在同一把锁内，多入口并发时同一步只算一次（均有测试覆盖）。

相关配置（`ReputationManager` 构造参数，`build_engine` 透传）：

| 参数 | 默认值 | 含义 |
|---|---|---|
| `recover_step_seconds` | `5.0` | 时间通道：熬满多久可完成一个恢复步 |
| `good_requests_per_step` | `3` | 良好行为通道：持续良好满 floor 后，需几个良好请求完成一个恢复步 |
| 良好步最短持续时间 floor | `0.4 × recover_step_seconds` = `2.0` | 未持续表现满该时长的请求不计信用（防瞬时刷量/并发灌入新等级） |
| `good_accel_steps` | `2` | 连续完成几个无违规恢复步后跳级直接回 `normal` |

> 对老行为的影响：**纯时间驱动的恢复节奏完全不变**（`recover_step_seconds`、
> `good_accel_steps` 默认值不变）；良好行为通道只会让“活跃且持续正常”的身份
> **更早**恢复，不改变任何违规/隔离结论。

### 4.5 状态回收与保留边界（长期运行状态规模有界）

回收在 `normal` 身份上进行（先按当前时间惰性推进状态机，避免把刚到期的身份误判
为闲置）。被回收的身份**真正从活动状态表删除**（旧实现只打 `archived` 标记、
条目仍留在内存里，导致身份数只涨不降）：

- **无隔离前科（`quarantine_count == 0`）**：状态与其事件流水**彻底删除**，
  内存立即释放。一次性身份（只来一两次、以后再不出现）走这条路径。
- **有隔离前科（`quarantine_count > 0`）**：活动状态删除，但在独立的
  **前科归档表**里只留一条最小结论
  （`client_id` + `quarantine_count` + `archived_at`）。该身份以后再出现时
  **原地复活**，`quarantine_count` 续上，再犯的隔离退避次数/时长与从未回收
  **完全一致**（不会退化成“第一次见”的最轻隔离）；归档身份本身不再占用
  活动状态规模。
- **前科归档也有界**：归档条目超过 `gc_history_ttl_seconds`（默认 **7 天**）
  未再出现会被**彻底遗忘**。因此无论见过多少身份，活动状态表 + 归档表的规模
  长期都有上界，不会随历史身份数无限增长。被彻底遗忘后再犯按首次身份处理
  （这是保留期边界的明确语义）。
- **绝不回收**：隔离中（`quarantined`）、观察恢复期（`restricted`/`suspect`）、
  以及最近 `gc_idle_seconds` 内有活动的身份；这些身份的状态与事件流水完整保留。

| 参数 | 默认值 | 含义 |
|---|---|---|
| `gc_idle_seconds` | `3600.0`（1 小时） | `normal` 身份闲置超过多久可被回收 |
| `gc_history_ttl_seconds` | `604800.0`（7 天） | 前科归档条目保留多久，超时彻底遗忘 |
| `gc_interval_seconds` | `60.0` | 请求路径上自动触发回收的间隔 |
| `max_events_per_client` | `100` | 每个身份事件流水最多保留条数（超出丢弃最旧） |
| `max_gc_events` | `100` | 全局 gc 事件最多保留条数（防止事件列表自身无限增长） |

- **触发方式**：`ReputationManager.gc(now)` 显式调用；或在请求路径上按
  `gc_interval_seconds` 自动触发。`build_engine` 透传上述全部参数。
- **回收统计**：`gc()` 返回
  `{reclaimed, archived, forgotten, archives_expired, states, archives}`，
  其中 `reclaimed` 为本次从活动表移除的全部身份（= `archived` ∪ `forgotten`），
  `states` / `archives` 为回收后两张表的规模；也可用
  `state_size()` / `archive_size()` 随时观测规模。
- 对老行为的影响：判定结论（等级、隔离退避次数/时长、恢复语义）均不变；变化的
  只是闲置身份从“打标记留在内存”改为“真正释放 / 留最小前科结论”。

### 4.6 持久化与可追溯

- 状态与事件流水以 JSON 原子写入 `data/reputation.json`（临时文件 + `os.replace`）。
- 进程重启后 `load()` 完整复现等级、隔离截止时间、隔离次数、恢复进度、
  良好信用 `good_credit` 与前科归档表（有重启复现测试）；旧版本只带
  `archived` 标记的状态文件在加载时会自动迁移到前科归档表并从活动表移除。
- 每次变更（`violation / escalate / quarantined / quarantine_released / recover /
  accelerated_recover / revived / gc`）都追加一条事件，形成审计轨迹，可通过
  `ReputationManager.events(client_id)` 查询。`recover` 事件带 `via` 字段
  （`time` / `good_behavior`）区分恢复推进来源。

## 5. 可解释性与日志

- 每次判定都通过 `logging` 打印：客户端、路径、原因（ALLOW/DENY）、规则 ID、
  以及包含限流窗口与信誉状态的**状态快照**。
- `Decision.snapshot`（以及 HTTP 响应体中的 `snapshot` 字段）包含：
  - `rate_limit`：本次档位（`tier_level`）、该档阈值、窗口、已用、剩余、窗口内时间戳；
  - `reputation`：等级、连续违规数、隔离次数、隔离截止与剩余时间、
    恢复进度（`recovery_progress`）、当前等级良好信用（`good_credit`）。
    放行响应还带 `good_behavior_level_after`（本次良好行为推进后的等级，
    下次请求生效；本次请求仍按进入时的档位判定）。

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
```

> 默认 HTTP 装配的恢复/回收参数面向长跑（观察步 5s、闲置回收 1h）。要在分钟级
> 手工观测“回收释放规模”和“良好行为加速”，建议用 Python 脚本 + 可控时钟，
> 或构造引擎时调小参数，例如：
>
> ```python
> from gateway.service import build_engine
> # 观察步 5s（良好步 floor=2s、每步 3 次良好请求）、闲置 30s 即回收、前科归档留 1h
> build_engine(gc_idle_seconds=30, gc_history_ttl_seconds=3600)
> ```

```python
# 手工验证脚本（可控虚拟时间，无需等待真实时长）：
import tempfile
from gateway.reputation import ReputationManager

m = ReputationManager(state_path=tempfile.mktemp(),
                      base_quarantine_seconds=10, recover_step_seconds=5,
                      gc_idle_seconds=5, gc_history_ttl_seconds=1000)

# 1) 回收真正释放规模：大量一次性身份 -> gc -> 活跃规模归零
for i in range(1000):
    m.get_level(f"once-{i}", 0.0)
print(m.state_size())          # 1000
print(m.gc(20.0)["states"])    # 0（旧实现这里仍是 1000）

# 2) 良好行为比熬时间更快：连续 3 次违规进入隔离（至 t=12），t=12 释放进观察期
c = "good"
for t in (0.0, 1.0, 2.0):
    m.record_violation(c, "rule", t)
m.get_level(c, 12.0)                              # restricted
for t in (14.0, 14.5, 15.0):                      # floor 2s 后 3 次良好
    m.note_good_request(c, t)
print(m.snapshot(c, 15.0)["level"])               # suspect（活跃路径）
for t in (17.0, 17.5, 18.0):
    m.note_good_request(c, t)
print(m.get_level(c, 18.0).value)                 # normal，观察期约 6s
# 对照“再不出现”的身份：t=18 还在 suspect，t=22 才 normal
```

### 测试覆盖一览

| 测试文件 | 覆盖内容 |
|---|---|
| `tests/test_rules.py` | 规则命中/不命中、方法限定、重复 rule_id |
| `tests/test_rate_limiter.py` | 阈值边界、窗口恢复、并发精确计数、身份隔离 |
| `tests/test_reputation.py` | 逐级升级、隔离拒绝、到期逐级恢复、观察期再犯加倍、重启复现、事件追溯 |
| `tests/test_tiered_rate_limit.py` | 分档默认值（normal 不变）、等级变化即时生效、分档阈值边界、隔离不占额度、并发分档精确计数、快照可见档位 |
| `tests/test_recovery_progress.py` | 加速恢复跳级、默认节奏与旧行为一致、再违规清零回退并重新隔离、进度重启复现（不白攒/不重攒）、并发只累计一次 |
| `tests/test_gc.py` | 闲置归档、隔离/观察期/活跃身份不回收、归档后结论重启复现、归档身份复活、事件保留边界、自动回收触发 |
| `tests/test_reclaim_and_recovery_bugfix.py` | **本轮修复专项**：回收真正缩小活跃规模（两波 500 身份）、四类受保护身份不误收、前科归档+重启退避一致、归档按保留期有界遗忘、良好行为比熬时间更快脱身、瞬时刷量最多推进一格、再违规清零回退并重新隔离、信用重启不白攒/不重攒、64 并发只推进一次、引擎层仅放行请求计良好 |
| `tests/test_engine.py` | 三维度联合判定、原因可区分、正常流量不误伤、隔离不占限流额度、200 并发不变量 |
| `tests/test_http.py` | 200/403/429 状态码与 `X-Deny-Reason` 头、响应内快照 |

## 7. 代码结构

```
gateway/
  models.py         # RequestContext / Rule / Decision / 原因与等级枚举
  rules.py          # 维度一：规则匹配
  reputation.py     # 维度二：信誉累积、隔离、退避恢复（时间+良好行为双通道）、良好信用持久化、真正回收+前科归档、JSON 持久化
  rate_limiter.py   # 维度三：线程安全滑动窗口（支持按次分档额度）
  engine.py         # 三维度编排、按等级分档限流、判定日志
  service.py        # 默认规则/分档阈值/恢复与回收参数的装配
main.py             # FastAPI 入口（create_app 工厂，多入口共用同一引擎）
tests/              # 全部单元与集成测试
data/reputation.json# 运行期信誉状态（已 gitignore）
```
