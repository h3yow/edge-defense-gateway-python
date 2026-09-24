# Edge Defense Gateway（本地请求防护网关）

一个基于 FastAPI 的**本地请求防护网关**：用本地持久化状态模拟客户端来源与信誉，
让**规则匹配、来源信誉、滑动窗口限流**三个维度在多个入口下给出一致、可解释、
可复现的判定。

## 1. 架构与判定模型

```
                 ┌──────────────────────────────────────────────┐
 HTTP 请求  ──▶  │                DefenseGateway                 │
 (X-Client-Id)   │  ① 规则匹配 RuleEngine                         │
                 │       └─ 命中 → deny/rule_violation + 登记违规  │
 /api/**         │  ② 隔离检查 ReputationManager                  │
 /portal/**      │       └─ 隔离中 → deny/in_quarantine            │
                 │  ③ 滑动窗口限流 SlidingWindowRateLimiter        │
                 │       └─ 超额 → deny/rate_limited（不影响信誉） │
                 │  ④ 全部通过 → allow，并清零连续违规计数          │
                 └───────────┬───────────────────┬────────────────┘
                             ▼                   ▼
                  data/client_states.json   data/audit.jsonl
                  （状态快照，原子写）        （追加式审计，逐条可追溯）
```

三个维度**同时**生效，任一不通过即拒绝，原因按固定优先级稳定可区分：

| reason（稳定字符串） | 含义 | HTTP 状态码 | 是否影响信誉 |
|---|---|---|---|
| `rule_violation` | 命中防护规则 | 403 | 是，登记一次违规 |
| `in_quarantine` | 处于隔离期，一切请求拒绝 | 403 | 否（隔离期内再违规会延长隔离） |
| `rate_limited` | 滑动窗口额度耗尽 | 429 | **否**，限流≠违规，二者可区分 |

> 注意：限流只反映"来得太快"，不计入违规、不升级信誉，因此**触发限流与触发拦截**
> 始终可从 reason、HTTP 状态码与审计事件三个层面区分。

### 1.1 默认防护规则（`edge_gateway/config.py`）

| 规则 ID | 描述 | 匹配范围 |
|---|---|---|
| R001 | 路径穿越（`../`、`..\` 及 `%2e%2e`、`%c0%af` 编码变体） | path |
| R002 | 管理/内部路径（`/admin/**`、`/.internal/**`，词边界匹配） | path |
| R003 | SQL 注入特征（`' or '1'='1`、`--`、`; drop table`、`union select`） | path/headers/body |
| R004 | XSS 特征（`<script>`、`javascript:`、`onerror=`、`onload=`） | path/headers/body |

规则按注册顺序求值、首个命中即返回；**不命中绝不误伤正常流量**
（如 `/v2/administration` 不会被 R002 拦截，有专门测试保证）。

## 2. 信誉累积、隔离与恢复模型（`edge_gateway/reputation.py`）

### 2.1 升级阶梯（基于连续违规 streak）

| 连续违规次数 | 信誉级别 | 行为 |
|---|---|---|
| 1 | NORMAL | 记录 |
| 2 | SUSPICIOUS（软告警） | 限流额度 ×0.5，仍服务；一次正常请求即解除 |
| 3 | SUSPICIOUS | 同上 |
| 4 | **QUARANTINE（第 1 次隔离）** | 30 秒内**一律拒绝** |

- 一次完整放行的请求会把连续违规计数清零。
- 隔离期内再次违规：**立即延长隔离**，退避公式
  `时长 = 30s × 2^(隔离次数-1)`，即 30s → 60s → 120s …
- 隔离释放后的恢复期内再次违规：立刻重新隔离，并使用下一档更长的时长。

### 2.2 隔离到期后的逐步恢复（退避恢复）

隔离到期后进入 SUSPICIOUS 恢复阶段，每经过一个冷却窗口（默认 15s）恢复一档额度：

| 释放后经过时间 | 恢复阶段 | 限流额度倍率 |
|---|---|---|
| 隔离未到期 | — | 0（一律拒绝） |
| 0 ~ 15s | stage 0 | ×0.25 |
| 15 ~ 30s | stage 1 | ×0.50 |
| ≥ 30s | 完全恢复 → NORMAL | ×1.00 |

默认限流策略：**每个身份 10 秒滑动窗口内 5 个请求**（可在 config 调整）。
时间相关行为全部通过可注入的 `Clock` 获取（测试用 `FakeClock`），
因此阈值与边界行为完全确定。

### 2.3 并发安全

- 限流：每身份一个时间戳 deque，**单锁原子完成"清理过期 → 判断 → 记账"**，
  并发请求计数不会丢失或重复；窗口内恰好达到阈值后，下一个请求确定被拒；
  窗口到期（最旧时间戳滑出边界）额度立即恢复。
- 网关：每个请求的三维判定在同一把串行锁内完成状态迁移，
  多个入口（`/api`、`/portal`）共享同一身份状态，结论一致。

### 2.4 持久化与可追溯（重启可复现）

- `data/client_states.json`：所有身份的信誉状态，临时文件 + `os.replace` 原子落盘。
- `data/audit.jsonl`：追加式 JSONL 审计，每次状态变更一行，事件类型包括
  `violation_registered`、`level_changed`、`quarantined`、
  `quarantine_extended`、`quarantine_released`、`recovered`，带单调序号与时间戳。
- 进程重启后从这两个文件重建内存状态，隔离剩余时间、隔离次数、恢复阶段完全复现
  （有跨"重启"测试与真实双实例冒烟验证）。

## 3. HTTP 接口

| 方法 & 路径 | 说明 |
|---|---|
| 任意 `/api/{path}` | 公共 API 入口（entrypoint=`api`） |
| 任意 `/portal/{path}` | Portal 入口（entrypoint=`portal`），共享同一套状态 |
| GET `/admin/clients/{identity}` | 查询身份信誉快照 + 滑动窗口状态 |
| GET `/` | 健康检查 |

身份由请求头 `X-Client-Id` 指定（缺省 `anonymous`），便于本地模拟不同来源。
放行返回 200（内含 decision 判定依据）；拒绝返回 403/429 与结构化 reason + 状态快照。

### 本地运行

```bash
uv sync
uv run uvicorn main:app --reload
# 正常请求
curl -H 'X-Client-Id: alice' http://127.0.0.1:8000/api/orders
# 状态快照
curl http://127.0.0.1:8000/admin/clients/alice
```

> 用 curl 构造路径穿越时它会在客户端归一化 `/../`；可使用编码形式
> `/api/%2e%2e/secret`，或在代码中直接调用 `DefenseGateway.inspect()`。

## 4. 验证方法

```bash
uv run pytest                      # 全部 29 个用例
uv run pytest -s -o log_cli=true   # 实时打印每条判定依据与状态快照
```

### 测试覆盖（`tests/`）

| 文件 | 覆盖点 |
|---|---|
| `test_rules_and_ratelimit.py` | 规则命中/不误伤、首条命中优先；限流**精确边界**（第 limit+1 个拒绝）、窗口到期恢复、身份隔离、**20 线程 ×10 次并发下计数恰好 100 放行/100 拒绝无丢失无重复** |
| `test_reputation.py` | streak 逐级升级、进入隔离、隔离期拒绝、三档退避恢复倍率、隔离中违规延长（30→60s）、恢复中违规重新隔离、正常请求清零、**状态与审计跨重建复现** |
| `test_gateway_integration.py` | 三维联合判定；三种 reason 可区分；限流不改信誉；两入口共享状态；隔离跨入口拒绝；恢复期限额 1→2→4 增长；16 线程下 50 放行/50 限流确定；**重启后仍处于隔离** |
| `test_http_api.py` | 真实 ASGI 请求：200/403/429、两入口共享限流计数、管理端快照 |

每个用例都会通过日志打印**判定依据**（verdict/reason/命中规则/限流明细）与
**客户端状态快照**（级别、streak、隔离到期时间、恢复阶段、倍率、窗口用量）。

## 5. 代码结构

```
edge_gateway/
  models.py       # 领域类型：RequestContext / Decision / Rule / ClientState / AuditEvent
  clock.py        # 可注入时钟（SystemClock / FakeClock）
  store.py        # JsonFileStore（JSON+JSONL 持久化）/ InMemoryStore
  rules.py        # 有序规则引擎
  ratelimit.py    # 线程安全滑动窗口限流器
  reputation.py   # 信誉升级 / 隔离 / 退避恢复
  gateway.py      # 三维联合判定编排
  config.py       # 默认规则与网关装配
main.py           # FastAPI：/api、/portal、/admin/clients
tests/            # 29 个单测/集成/HTTP 用例
```
