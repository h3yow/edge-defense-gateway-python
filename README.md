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
│ 维度 3 滑动窗口 SlidingWindowRateLimiter.check（原子：判定+登记）            │
│   超限 → 拒绝 rate_limited（429）；通过 → 放行 200                           │
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

- 基于身份的滑动窗口：每个 `client_id` 一个时间戳列表，默认 `10 次 / 1s`。
- `check()` 在同一把锁内完成「淘汰过期 → 比较阈值 → 追加登记」，
  并发请求计数**不丢失、不重复**（1000 并发 / 阈值 500 的测试严格验证）。
- 边界确定：窗口采用左开（边界时间戳过期），第 `limit` 次请求放行、第 `limit+1` 次拒绝。
- 窗口过期后时间戳被淘汰，额度自动恢复；不同身份计数完全隔离。

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

### 4.4 持久化与可追溯

- 状态与事件流水以 JSON 原子写入 `data/reputation.json`（临时文件 + `os.replace`）。
- 进程重启后 `load()` 完整复现等级、隔离截止时间、隔离次数（有重启复现测试）。
- 每次变更（`violation / escalate / quarantined / quarantine_released / recover`）
  都追加一条事件，形成审计轨迹，可通过 `ReputationManager.events(client_id)` 查询。

## 5. 可解释性与日志

- 每次判定都通过 `logging` 打印：客户端、路径、原因（ALLOW/DENY）、规则 ID、
  以及包含限流窗口与信誉状态的**状态快照**。
- `Decision.snapshot`（以及 HTTP 响应体中的 `snapshot` 字段）包含：
  - `rate_limit`：阈值、窗口、已用、剩余、窗口内时间戳；
  - `reputation`：等级、连续违规数、隔离次数、隔离截止与剩余时间。

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

运行测试（含并发、阈值边界、隔离恢复、重启复现、正常流量不误伤；
日志中会打印判定依据与状态快照）：

```bash
uv run pytest -q                      # 静默概要
uv run pytest -o log_cli=true         # 查看每条用例的判定依据与快照
uv run pytest tests/test_engine.py    # 仅编排层测试
```

### 测试覆盖一览

| 测试文件 | 覆盖内容 |
|---|---|
| `tests/test_rules.py` | 规则命中/不命中、方法限定、重复 rule_id |
| `tests/test_rate_limiter.py` | 阈值边界、窗口恢复、并发精确计数、身份隔离 |
| `tests/test_reputation.py` | 逐级升级、隔离拒绝、到期逐级恢复、观察期再犯加倍、重启复现、事件追溯 |
| `tests/test_engine.py` | 三维度联合判定、原因可区分、正常流量不误伤、隔离不占限流额度、200 并发不变量 |
| `tests/test_http.py` | 200/403/429 状态码与 `X-Deny-Reason` 头、响应内快照 |

## 7. 代码结构

```
gateway/
  models.py         # RequestContext / Rule / Decision / 原因与等级枚举
  rules.py          # 维度一：规则匹配
  reputation.py     # 维度二：信誉累积、隔离、退避恢复、JSON 持久化
  rate_limiter.py   # 维度三：线程安全滑动窗口
  engine.py         # 三维度编排与判定日志
  service.py        # 默认规则/阈值/状态路径的装配
main.py             # FastAPI 入口（create_app 工厂，多入口共用同一引擎）
tests/              # 全部单元与集成测试
data/reputation.json# 运行期信誉状态（已 gitignore）
```
