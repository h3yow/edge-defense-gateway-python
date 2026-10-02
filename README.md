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
│ 周期性回收（每 reap_interval_seconds）：不活跃身份软回收 + 历史裁剪           │
│ 维度 1 规则匹配 RuleEngine.match                                             │
│   命中 → 拒绝 rule_matched（403），并向信誉系统登记一次 rule_matched 违规     │
│ 维度 2 信誉隔离 ReputationManager.note_clean_activity                        │
│   隔离中 → 拒绝 quarantined（403），隔离期一律拒绝、不消耗限流额度；          │
│   非隔离请求同时上报“干净活动”，累计观察恢复期的良好表现进度                  │
│ 维度 3 滑动窗口 SlidingWindowRateLimiter.check（原子：判定+登记）             │
│   按当前信誉等级取分档阈值，超限 → 拒绝 rate_limited（429）；通过 → 放行 200  │
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

## 3. 速率模型（`gateway/rate_limiter.py`）

### 3.1 滑动窗口基本语义

- 基于身份的滑动窗口：每个 `client_id` 一份窗口时间戳历史，默认 `10 次 / 1s`。
- `check()` 在同一把锁内完成「淘汰过期 → 比较阈值 → 追加登记」，
  并发请求计数**不丢失、不重复**（1000 并发 / 阈值 500 的测试严格验证）。
- 边界确定：窗口采用左开（边界时间戳过期），第 `limit` 次请求放行、第 `limit+1` 次拒绝。
- 窗口过期后时间戳被淘汰，额度自动恢复；不同身份计数完全隔离。

### 3.2 信誉分档限流（新）

限流阈值不再对所有身份“一刀切”，而是随信誉等级递减。**同一身份只有一份窗口
历史**，等级一旦变化，下一次请求立即按新档位阈值判定，无需等窗口滑动：

| 信誉等级 | 默认阈值（次/窗口） | 含义 |
|---|---|---|
| `normal` | `10` | 与历史默认完全一致（老行为不变） |
| `suspect` | `5` | 可疑身份收窄额度 |
| `restricted` | `2` | 限制观察期进一步收窄 |
| `quarantined` | 直接拒绝（阈值 0，且在限流维度之前拦截，不占额度） | 隔离身份 |

- 分档表可整体自定义：`build_engine(tier_limits={ReputationLevel.SUSPECT: 3, ...})`，
  表中缺失的档位回落到统一 `limit`；
  传 `tier_limits=TIER_LIMITS_DISABLED` 可关闭分档、退回所有身份统一阈值的老模式。
  直接构造 `DefenseEngine(..., tier_limits=None)` 同样是不分档的老行为。
- 阈值边界依旧确定：以 `restricted=2` 为例，窗口内第 2 次放行、第 3 次拒绝；
  多入口并发下放行数严格等于档位阈值（有并发单测严格断言）。
- 每次判定的 `snapshot.rate_limit` 都能看到这次用了哪一档、还剩多少额度：

  ```json
  {"tier": "suspect", "limit": 5, "window_seconds": 1.0,
   "used": 5, "remaining": 0, "timestamps": [...]}
  ```

  HTTP 响应体的 `snapshot.rate_limit` 字段同构；限流拒绝的 `detail` 也会注明
  所属档位（如“超过信誉档位 restricted 的滑动窗口限额 2 次/1s”）。

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
duration = min(max_quarantine_seconds, base_quarantine_seconds × 2^(quarantine_count - 1))
```

默认 `base=10s`、封顶 `300s`，即第 1 次隔离 10s、第 2 次 20s、第 3 次 40s……
隔离期内**所有请求一律拒绝**（即使路径正常），原因恒为 `quarantined`，且不消耗
任何限流额度。

### 4.3 隔离到期后的逐级恢复

状态推进是**时间驱动**的（任何一次查询/请求都会惰性推进，无需后台线程）：

```
quarantined ──到期──▶ restricted ──满一个观察步──▶ suspect ──满一个观察步──▶ normal
```

观察步长 `recover_step_seconds` 默认 **5s**。隔离到期先降为 `restricted` 观察期，
请求恢复放行（仍受规则与分档限流约束）。

### 4.4 观察恢复期“表现好更快脱身”（新）

恢复期进度 `good_progress` 由两部分构成：

1. **自然时间（保底，与老版本完全一致）**：进入当前等级后每真实经过 1 秒，
   进度计 1 秒。即使身份完全静默，节奏也与升级前相同（5s 降一级）；
2. **良好表现奖励（加速）**：观察期（`restricted`/`suspect`）内每经过
   `good_bonus_interval_seconds`（默认 **0.5s**）且期间没有新违规，身份来一次
   未命中规则的请求，进度额外 `+good_bonus_seconds`（默认 **1s**）。
   积极保持正常活动时，恢复最快可比纯等待快约一半。

规则要点：

- 进度满 `recover_step_seconds` 即降一级，降档时进度清零重新累计；
- 奖励发放按 `last_bonus_at` 锚点节流，**并发请求在同一间隔内只发一次**，
  计数不会被多算（32 并发同时刻的测试严格验证）；
- 观察期内**任何新违规立即清零进度与奖励锚点**，并按连续违规规则立刻回退
  （`suspect → restricted`）或重新隔离（`restricted` 下再犯 `quarantine_count+1`、
  时长翻倍）；
- 进度、锚点随每次变化原子落盘，重启后按锚点继续累计——
  **不白攒（进度完整恢复）也不重复攒（重启本身不发奖励）**。

相关参数（均可在 `ReputationManager` / `build_engine` 配置）：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `recover_step_seconds` | `5.0` | 降一级所需的观察进度秒数 |
| `good_bonus_seconds` | `1.0` | 每次良好表现奖励的进度秒数；置 `0` 即退化为纯时间恢复（老行为） |
| `good_bonus_interval_seconds` | `0.5` | 两次良好奖励之间的最小间隔（节流/并发去重） |

`good_progress` 事件会写入审计流水，`snapshot.reputation.recover_progress`
暴露当前进度（形如 `3.5/5s`）。

### 4.5 状态回收与有界保留（新）

长时间运行下身份状态与事件流水不能无限膨胀。回收分两级：

1. **软回收（活跃 → 休眠 dormant）**：活跃身份自 `last_seen` 起超过
   `inactive_ttl_seconds`（默认 **3600s**）未出现，且当前为 `normal` 时，
   转为休眠身份——活动态（等级/违规计数/窗口）全部清空，仅保留
   `client_id`、历史隔离次数 `quarantine_count`、`last_seen`。
   - **隔离中的身份绝不回收**（即使长期无活动）；
   - **观察恢复期中（`restricted`/`suspect`）的身份绝不回收**；
   - 最近有活动的身份（静默时长 ≤ ttl）保留全部状态；
   - 边界确定：静默时长 **恰好等于 ttl 保留**，严格大于才回收。
2. **硬遗忘（休眠 → 删除）**：休眠身份超过 `dormant_ttl_seconds`
   （默认 **86400s = 1 天**）仍未出现，则真正遗忘；休眠身份数量超过
   `max_dormant_identities`（默认 **1000**）时，按 `last_seen` 淘汰最旧的。
3. **休眠身份再次出现**：自动唤醒（审计事件 `revived`），活动结论按全新正常
   身份处理，**但历史隔离次数被带回**——下次再犯仍按第 N+1 次隔离退避，
   不会因为被回收过就退回到“从没见过”。
4. **历史记录有界**：事件流水最多保留 `max_events` 条（默认 **2000**，最旧先丢，
   每次落盘前裁剪）；身份被软回收时其历史事件一并删除。

回收由引擎周期性触发（`reap_interval_seconds`，默认 **60s**，并发下有锁保证
一轮只执行一次），同时同步清理限流器中对应身份的窗口计数；也可直接调用
`ReputationManager.reap_inactive(now)` 手动触发。休眠集合随状态文件落盘，
**重启后回收结论完整复现**（休眠集合、隔离次数延续均有测试）。

| 参数 | 默认值 | 说明 |
|---|---|---|
| `inactive_ttl_seconds` | `3600.0` | 正常身份多久不活动后软回收 |
| `dormant_ttl_seconds` | `86400.0` | 休眠身份多久后彻底遗忘 |
| `max_dormant_identities` | `1000` | 休眠身份数量上限（超量淘汰最旧） |
| `max_events` | `2000` | 事件流水保留条数上限（最旧先丢） |
| `reap_interval_seconds` | `60.0` | 引擎自动回收的执行间隔 |

### 4.6 持久化与可追溯

- 状态（含恢复期进度、最近活动时间、休眠身份集合）与事件流水以 JSON 原子写入
  `data/reputation.json`（临时文件 + `os.replace`）；旧版本文件可直接加载，
  缺失的新字段按默认值补齐。
- 进程重启后 `load()` 完整复现等级、隔离截止时间、隔离次数、恢复进度与休眠集合。
- 每次变更（`violation / escalate / quarantined / quarantine_released / recover /
  good_progress / progress_reset / revived`）都追加一条事件，形成审计轨迹，
  可通过 `ReputationManager.events(client_id)` 查询。

## 5. 可解释性与日志

- 每次判定都通过 `logging` 打印：客户端、路径、原因（ALLOW/DENY）、规则 ID、
  本次命中的信誉**档位**以及包含限流窗口与信誉状态的**状态快照**。
- `Decision.snapshot`（以及 HTTP 响应体中的 `snapshot` 字段）包含：
  - `rate_limit`：信誉档位 `tier`、生效阈值 `limit`、窗口、已用、剩余
    （`remaining`）、窗口内时间戳；
  - `reputation`：等级、连续违规数、隔离次数、隔离截止与剩余时间、
    恢复进度 `recover_progress` 与观察步长、最近活动时间。

## 6. 运行与验证

```bash
# 安装依赖（需 uv）
uv sync

# 启动服务
uv run uvicorn main:app --reload

# 示例：正常请求（normal 档仍是 10/s，响应里能看到 tier 与 remaining）
curl -s -H 'X-Client-Id: alice' http://127.0.0.1:8000/gateway/home | jq

# 示例：命中规则（连续 3 次后该身份进入隔离；第 2 次后为 restricted 档，仅 2/s）
for i in 1 2 3; do
  curl -s -i -H 'X-Client-Id: scanner' http://127.0.0.1:8000/gateway/admin | grep -i 'x-deny-reason'
done

# 示例：触发分档限流（restricted 身份连打正常路径，第 3 次 429，响应可见 tier/remaining）
for i in 1 2 3; do
  curl -s -H 'X-Client-Id: watch' http://127.0.0.1:8000/gateway/home | jq '.snapshot.rate_limit | {tier, limit, remaining}'
done
```

运行测试（含分档阈值确定性与并发计数、良好加速恢复与再犯回退、回收边界取舍、
各状态重启复现；日志中会打印每条用例的场景、结论与关键状态）：

```bash
uv run pytest -q                      # 静默概要（49 个用例）
uv run pytest -o log_cli=true         # 查看每条用例的判定依据与快照
uv run pytest tests/test_tiered_rate_limit.py   # 仅分档限流
uv run pytest tests/test_good_progress.py       # 仅恢复期加速
uv run pytest tests/test_reaping.py             # 仅回收与保留
```

### 测试覆盖一览

| 测试文件 | 覆盖内容 |
|---|---|
| `tests/test_rules.py` | 规则命中/不命中、方法限定、重复 rule_id |
| `tests/test_rate_limiter.py` | 阈值边界、窗口恢复、并发精确计数、身份隔离 |
| `tests/test_reputation.py` | 逐级升级、隔离拒绝、到期逐级恢复、观察期再犯加倍、重启复现、事件追溯 |
| `tests/test_tiered_rate_limit.py` | **默认档 normal 额度不变、各档阈值边界、档位即时切换、隔离不占额度、分档并发精确计数、自定义/关闭分档** |
| `tests/test_good_progress.py` | **良好请求加速恢复、纯等待节奏不变、再犯进度清零并回退、suspect 回退、并发不重复计奖、重启进度不丢不重、奖励可关闭** |
| `tests/test_reaping.py` | **软回收与休眠保留、ttl 边界确定性、隔离/观察期豁免、近期活动保留、休眠再犯延续退避、休眠 ttl/容量有界、重启一致、事件有界、引擎周期回收联动清窗** |
| `tests/test_engine.py` | 三维度联合判定、原因可区分、正常流量不误伤、隔离不占限流额度、200 并发不变量 |
| `tests/test_http.py` | 200/403/429 状态码与 `X-Deny-Reason` 头、响应内快照、**分档额度与 remaining 可见** |

## 7. 对老行为的影响

- **默认配置下正常身份的判定结论与额度完全不变**：normal 档阈值仍取
  `build_engine(limit=...)` 的 `10 次/1s`；不积极活动的身份恢复节奏仍是
  每 5s 降一级（良好奖励需要观察期内主动请求才会产生）。
- 直接构造 `DefenseEngine` 不传 `tier_limits` 时，限流维度不做任何分档，
  与历史行为逐条等价；`SlidingWindowRateLimiter.check()` 新增的 `limit`
  参数默认缺省即旧阈值。
- 落盘文件向后兼容：旧的 `reputation.json` 可直接加载，新字段缺失时自动补默认值；
  新文件多出 `dormant` 段与状态新字段。
- 唯一的额外默认动作是引擎每 60s 尝试一次回收；默认 ttl 为 1 小时，
  正常在线身份、隔离中与恢复期中身份都不受影响。

## 8. 代码结构

```
gateway/
  models.py         # RequestContext / Rule / Decision / 原因与等级枚举
  rules.py          # 维度一：规则匹配
  reputation.py     # 维度二：信誉累积、隔离、加速恢复、回收、JSON 持久化
  rate_limiter.py   # 维度三：线程安全滑动窗口（支持按调用传入分档阈值）
  engine.py         # 三维度编排、分档取值、周期回收、判定日志
  service.py        # 默认规则/阈值/分档/回收参数/状态路径的装配
main.py             # FastAPI 入口（create_app 工厂，多入口共用同一引擎）
tests/              # 全部单元与集成测试
data/reputation.json# 运行期信誉状态（已 gitignore）
```
