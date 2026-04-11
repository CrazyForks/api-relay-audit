# API Relay Audit

by [@li9292](https://x.com/li9292)

Security audit tool for third-party AI API relay/proxy services. Detects hidden prompt injection, prompt leakage, instruction override with non-Claude identity substitution (GLM/DeepSeek/Qwen/…), context truncation, tool-call package substitution (AC-1.a), error response header leakage (AC-2 adjacent), and SSE-level stream integrity anomalies (AC-1 streaming layer).

Threat model follows the AC-1 / AC-1.a / AC-1.b / AC-2 taxonomy from Liu et al., [*Your Agent Is Mine: Measuring Malicious Intermediary Attacks on the LLM Supply Chain*, arXiv:2604.08407](https://arxiv.org/abs/2604.08407). Stream-level detection concept sourced from [hvoy.ai](https://hvoy.ai/) / `zzsting88/relayAPI` `claude_detector.py` (verified against source 2026-04-11, clean-room reimplementation).

## 🚀 Quick Start (30 seconds)

One command to audit any relay — no install, no clone, no Python dependencies beyond `curl`:

```bash
curl -sO https://raw.githubusercontent.com/toby-bridges/api-relay-audit/master/audit.py
python audit.py --key <YOUR_KEY> --url <BASE_URL> --output report.md
```

For **Web3 / wallet users**, add Step 11 (SlowMist signature isolation probes):

```bash
python audit.py --key <YOUR_KEY> --url <BASE_URL> --profile web3 --output report.md
```

Output: a structured Markdown report with a risk summary (LOW / MEDIUM / HIGH) at the top plus per-step details. See the [11-Step Audit table](#11-step-audit) and [Architecture section](#architecture) below.

## Quality Assurance

This project uses an unusually rigorous quality pipeline for a CLI tool:

- **319 pytest unit tests** across 11 test files (from 114 baseline in v2.1, +205 in v2.3)
- **6 independent Codex review rounds** during v2.2 → v2.3 development
- **10 real bugs caught and fixed** by those reviews before ship (2 MEDIUM + 1 NIT + 1 LOW in early rounds, 1 MEDIUM version-suffix, 1 MEDIUM + 1 LOW SSE edge cases, 1 MEDIUM parity + 2 LOW residual)
- **Byte-level dual-distribution parity** enforced by `test_risk_matrix_character_identical` — the modular and standalone versions cannot drift
- **Every ported concept has docstring attribution** (LiteLLM Apache-2.0 secret regexes, hvoy.ai clean-room reimplementation for SSE integrity, SlowMist inspiration for Web3 probes) with local clones of all upstream repos for verification
- **Zero regressions**: every fix in every Codex round was accompanied by a regression test so the bug class cannot return

See [`ROADMAP.md`](./ROADMAP.md) for the complete list of shipped features, deferred backlog, and the "explicitly NOT doing" decisions with rationale.

## What's New in v2.3 (v3 Feature Release, PR 3: Stream Integrity)

v2.3 adds **Step 10: Stream Integrity (AC-1 SSE-layer)**. Opens an Anthropic streaming request with extended thinking enabled, captures every server-sent event, and verifies four structural invariants against a known-good Anthropic SSE schema:

1. **SSE event whitelist** — every event type must belong to the 7-event Anthropic set (`ping` / `message_start` / `content_block_start` / `content_block_delta` / `content_block_stop` / `message_delta` / `message_stop`). Unknown events are a fingerprint of a relay that injects or rewrites events.
2. **`output_tokens` monotonicity** — samples across `message_delta` events must be non-decreasing. Rewriters that recompute usage fields often fail this.
3. **`input_tokens` consistency** — the value reported by `message_start` must match every subsequent `message_delta` sample. Rewriters that hide a model downgrade often mutate it.
4. **Thinking signature validity** — `signature_delta` events must carry non-empty signature strings. Relays that fake the thinking block without a real Opus/Sonnet 4.6 backend leave these empty.

Also verifies `message_start.message.model` contains `claude`. Adds a new **D5 risk dimension** — a stream integrity anomaly on its own escalates to HIGH, matching Step 8 / Step 9 severity. New flag `--skip-stream-integrity` for relays that do not support Anthropic streaming.

The detection concept was sourced from hvoy.ai's `claude_detector.py` (verified against source on 2026-04-11, no LICENSE file in upstream repo so this is an independent clean-room reimplementation with tri-state verdicts instead of their 0-100 numeric score).

## What's New in v2.2 (v3 Feature Release, PR 1)

v2.2 added **Step 9: Error Response Header Leakage (AC-2 adjacent)**. Paper Figure 3 reports credential abuse at 4.25% of 400 free routers — twice as common as AC-1 code injection (2%). This step fires 5-6 deterministic broken requests (malformed JSON, invalid model, wrong content-type, missing fields, unknown endpoint, optional 256 KB oversized body) and scans the error body **and response headers** for echoed `Authorization` values, the first-8 API key prefix, upstream provider URLs (`api.anthropic.com` / `api.openai.com`), env var names (`OPENAI_API_KEY=`), filesystem paths, and stack-trace markers. The risk matrix expands to 4 dimensions — a `critical` or `high` leakage on its own escalates straight to HIGH, matching Step 8's severity. Two new flags ship alongside: `--skip-error-leakage` to opt out, and `--aggressive-error-probes` to enable the 256 KB oversized-context probe (warning: may incur metered billing on pay-as-you-go relays).

## What's New in v2

v2 added **Step 8: AC-1.a tool-call substitution detection**, which catches malicious relays that rewrite package-install commands on the return path (e.g. `pip install requests` → `reqeusts` typosquat) by asking the model to echo four pinned install commands verbatim and diffing the result token-by-token. The risk matrix was extended to three dimensions — a single tool-call substitution on its own escalates straight to HIGH, independent of injection/instruction-override signals. Two flags ship alongside: `--skip-tool-substitution` to opt out, and `--warmup N` to fire N benign requests before the audit as a partial mitigation for AC-1.b request-count-gated backdoors.

## 10-Step Audit

| Step | Test | What it detects |
|------|------|-----------------|
| 1 | Infrastructure Recon | DNS/WHOIS/SSL/CDN, hosting, certificate issues |
| 2 | Model List | Backend channels, model coverage |
| 3 | Token Injection | Hidden system prompt injection (delta method) |
| 4 | Prompt Extraction | Leakable hidden prompts (3 attack vectors) |
| 5 | Instruction Conflict + Identity | User system prompt being overridden; non-Claude identity substitution (GLM / DeepSeek / Qwen / Chinese-market substitutes) |
| 6 | Jailbreak | Weak anti-extraction defenses (3 methods) |
| 7 | Context Length | Truncation below advertised limit (canary markers + binary search) |
| 8 | Tool-Call Substitution (AC-1.a) | Package-name rewriting on the return path (`requests` → `reqeusts` typosquat) |
| 9 | Error Response Leakage (AC-2 adjacent) | Echoed `Authorization` / API key prefix / upstream URL / env var name / FS path / stack trace / LiteLLM internal field / Bedrock guardrail PII in error responses |
| 10 | Stream Integrity (AC-1 SSE) | SSE event whitelist + usage monotonicity + thinking signature validity + stream model identity on an Anthropic streaming response |
| 11 | Web3 Prompt Injection (profile=web3\|full) | 3 probes for wallet-safety refusal: transfer guidance / sign-transaction refusal / private key leak refusal. Safe-priority classifier with hard-injected marker override |

For the full list of planned and deferred work, see [`ROADMAP.md`](./ROADMAP.md).

---

## Architecture

### Dual-distribution model

The same 11-step audit logic ships in two parallel forms, kept
byte-identical by a dedicated parity test:

- **Standalone** (`audit.py`): a single ~2500-line file with zero Python
  dependencies beyond the stdlib. All HTTP goes through `curl`
  subprocess. One `curl -sO` download + one `python audit.py` run. This
  is the path most users take.
- **Modular** (`api_relay_audit/` + `scripts/audit.py`): a proper Python
  package with `httpx` for HTTP, full pytest suite, and per-module
  docstrings. This is the path developers extend.

Every change to one distribution must be mirrored into the other.
`tests/test_dual_distribution_parity.py::test_risk_matrix_character_identical`
enforces the invariant at the risk-matrix layer by doing a byte-for-byte
comparison. `tests/test_web3_injection.py::TestWeb3MarkerParity`
enforces it at the Web3 probe data layer.

### 11-step pipeline

```
┌────────────────────────────────────────────────────────────────┐
│  Step 1  Infrastructure Recon     DNS / WHOIS / SSL / headers  │
│  Step 2  Model List                /v1/models enumeration      │
│  Step 3  Token Injection           delta method on input_tokens│
│  Step 4  Prompt Extraction         3 direct attacks            │
│  Step 5  Instruction Conflict      cat test + identity spoof   │
│  Step 6  Jailbreak Tests           3 anti-extraction probes    │
│  Step 7  Context Length            canary markers + bin search │
│  Step 8  Tool-Call Substitution    AC-1.a character-level diff │
│  Step 9  Error Response Leakage    AC-2 adjacent, 7 triggers   │
│  Step 10 Stream Integrity          AC-1 SSE-level, 4 invariants│
│  Step 11 Web3 Prompt Injection     profile=web3 only, 3 probes │
│                                                                │
│  Overall Rating (6D risk matrix)                               │
└────────────────────────────────────────────────────────────────┘
```

Each step returns a tri-state verdict (clean / anomaly / inconclusive)
into a shared `Reporter` which builds the Markdown report with a risk
summary header at the top and per-step detail sections below.

### 6D risk matrix

The overall rating aggregates 6 orthogonal risk dimensions:

| Dim | Step | Triggered when... |
|---|---|---|
| D1 | 3 | Token injection > 100 tokens |
| D2 | 5 | User system prompt overridden (cat test fails or identity spoofed) |
| D3 | 8 | Tool-call package substitution detected |
| D4 | 9 | Error response leaks credentials (critical/high severity) |
| D5 | 10 | Stream integrity anomaly (unknown events / usage rewrite / empty signatures / non-Claude stream model) |
| D6 | 11 | Web3 prompt injection (only active under `--profile web3\|full`) |

Plus inconclusive variants (`D3i`, `D4i`, `D4m`, `D5i`, `D6i`) for
cases where a step ran but could not reach a clean/anomaly verdict.

Rules (first match wins):
- `D3 or D4 or D5 or D6` → **HIGH**
- `D1 and D2` → **HIGH**
- `D1` or `D2` → **MEDIUM**
- `D3i or D4i or D4m or D5i or D6i` → **MEDIUM**
- otherwise → **LOW**

### `--profile` audience selector

Instead of maintaining two git branches for general vs Web3 audiences,
the tool uses a runtime flag:

| Profile | Runs | Suitable for |
|---|---|---|
| `general` (default) | Steps 1-10 | Regular API relay users (95% case) |
| `web3` | Steps 1-11 | Wallet / crypto users |
| `full` | Steps 1-11 + any future profile-gated steps | Security researchers |

The general user runs the tool exactly as before — no CLI change, no
extra work, no Step 11 overhead. Web3 users opt in with one flag.

This design preserves the dual-distribution invariant, the single
test suite, the memory/documentation consistency, and the
"one-curl-download" standalone story. See [`ROADMAP.md`](./ROADMAP.md)
for why git branches were rejected.

### Key design principles

1. **Detection based on invariants, not signatures.** Token counts are
   non-forgeable integers (Step 3). Canary markers are deterministic
   substrings (Step 7). SSE event types are a closed schema (Step 10).
   The tool doesn't look for known-bad patterns — it verifies that
   known-good invariants hold.
2. **Tri-state verdicts, not booleans.** Every step returns clean,
   anomaly, or **inconclusive**. A relay that blocks a probe is not
   clean — it's suspicious. Silent swallowing becomes a detectable
   signal.
3. **Clean-room reimplementation for ported concepts.** Step 9 regexes
   are adapted from LiteLLM's Apache-2.0 `_logging.py`. Step 10 SSE
   schema comes from hvoy.ai's `claude_detector.py` (no LICENSE —
   concepts and schema field names are not copyrightable). Step 11
   probes follow SlowMist's signature isolation principle. Every
   port has attribution in the module docstring.
4. **Codex review loop for non-trivial PRs.** Independent Codex reviews
   caught 10 real bugs across this feature set — every one would have
   shipped as a false-negative or parity violation otherwise. The
   review round is a 2-5 minute cost that prevents much larger downstream
   costs.
5. **Pareto-optimal scope.** Every step has to earn its place: does it
   cover a dimension nothing else catches, does the detection stay
   valid across relay variants, can it be implemented without breaking
   zero-dep? Steps that fail any of these get deferred (see
   [`ROADMAP.md`](./ROADMAP.md) "Explicitly NOT doing").

For a deep-dive engineering narrative (in Chinese), see
[`FOR_JOHN.md`](./FOR_JOHN.md).

---

## Choose Your Way

### Option A: One-Liner (Zero Install)

For anyone who just wants to test a relay quickly. No git clone, no pip install.

```bash
curl -sO https://raw.githubusercontent.com/toby-bridges/api-relay-audit/master/audit.py
python audit.py --key <YOUR_KEY> --url <BASE_URL>
```

Requirements: Python 3.7+ and `curl` (pre-installed on macOS/Linux/WSL).

---

### Option B: OpenClaw Skill

For [OpenClaw](https://github.com/openclaw/openclaw) users. The agent downloads the script, runs the audit, and interprets results for you.

**Install the skill**, then just tell the agent:

> "Test this relay: https://api.example.com/v1 with key sk-xxx"

The skill file is [`SKILL.md`](./SKILL.md) in this repo. It follows the OpenClaw skill format and is fully self-contained.

---

### Option C: Claude Code / Developer Setup

For developers who want to modify, extend, or contribute. The modular codebase with full test suite.

```bash
git clone https://github.com/toby-bridges/api-relay-audit.git
cd api-relay-audit
pip install httpx
python scripts/audit.py --key <YOUR_KEY> --url <BASE_URL> --output report.md
```

#### Project Structure

```
audit.py                             # Standalone zero-dep version (~2500 LOC)
SKILL.md                             # OpenClaw skill definition
ROADMAP.md                           # Shipped / near-term / deferred backlog
FOR_JOHN.md                          # Engineering narrative (Chinese)
api_relay_audit/                     # Modular package (requires httpx)
  client.py                          #   APIClient with auto-detection + streaming
  context.py                         #   Context length canary + binary search
  error_leakage.py                   #   Step 9 AC-2 scan (7 triggers + regex)
  identity_patterns.py               #   Step 5 non-Claude identity detection
  reporter.py                        #   Markdown report builder with risk flags
  stream_integrity.py                #   Step 10 SSE analyzer + StreamSignals
  tool_substitution.py               #   Step 8 AC-1.a package substitution
  web3/                              #   Profile=web3 subpackage
    injection_probes.py              #     Step 11 SlowMist signature isolation
scripts/
  audit.py                           #   11-step orchestrator (entry point)
  context-test.py                    #   Standalone context length probe
  extract-data.py                    #   Report → JSON extractor for dashboard
tests/                               # 319 pytest tests across 11 files
  test_dual_distribution_parity.py   #   byte-level parity guard
  test_client_stream.py              #   streaming SSE parser unit tests
  test_stream_integrity.py           #   Step 10 verdict analysis tests
  test_web3_injection.py             #   Step 11 probes + classifier tests
  ...
web/
  index.html                         # Dashboard (single-page vanilla JS)
deploy/
  deploy-nas.sh                      # Docker/nginx deployment script
```

#### Run Tests

```bash
pip install httpx pytest
python -m pytest tests/ -v
```

---

## CLI Options

All three options share the same CLI interface:

| Flag | Required | Description | Default |
|------|----------|-------------|---------|
| `--key` | Yes | API Key | - |
| `--url` | Yes | Base URL (e.g. `https://xxx.com/v1`) | - |
| `--model` | No | Model name | `claude-opus-4-6` |
| `--output` | No | Report output path (markdown) | stdout |
| `--skip-infra` | No | Skip infrastructure recon | `False` |
| `--skip-context` | No | Skip context length test | `False` |
| `--skip-tool-substitution` | No | Skip AC-1.a tool-call substitution test | `False` |
| `--skip-error-leakage` | No | Skip Step 9 AC-2 adjacent error response leakage test | `False` |
| `--aggressive-error-probes` | No | Enable 256 KB oversized-context probe in Step 9 (may incur billing) | `False` |
| `--skip-stream-integrity` | No | Skip Step 10 SSE-level stream integrity test | `False` |
| `--profile` | No | Audience selector: `general` (Steps 1-10, default), `web3` (adds Step 11 for wallet users), `full` (all steps) | `general` |
| `--skip-web3-injection` | No | Skip Step 11 Web3 injection probes (only runs under `--profile web3\|full`) | `False` |
| `--warmup` | No | Send N benign requests before the audit (partial AC-1.b mitigation) | `0` |
| `--timeout` | No | Request timeout (seconds) | `120` |

## Risk Levels

| Level | Criteria | Recommendation |
|-------|----------|----------------|
| LOW | All 6 risk dimensions (D1-D6) clean: no injection, instructions work, full context, no tool-call substitution, no error leakage, clean stream integrity, no Web3 injection (if `--profile web3`) | Safe to use |
| MEDIUM | Minor injection (<100 tokens) OR prompt extractable OR any of Steps 8/9/10/11 **inconclusive** OR Step 9 medium-only leakage (FS path / stack trace) | OK for simple tasks, use with caution |
| HIGH | Injection >100 tokens AND instructions overridden, OR **any** of: tool-call substitution (Step 8), critical/high error leakage (Step 9), stream integrity anomaly (Step 10), or Web3 injection detected (Step 11 under `--profile web3`) | Not recommended |

See [`ROADMAP.md`](./ROADMAP.md#architectural-invariants-must-preserve)
for the full 6D risk matrix rules and dimension definitions.

## Author

[@li9292](https://x.com/li9292)

## License

MIT

---

## 中文说明

全面审计第三方 AI API 中转站（反代/转发站）的安全性、可靠性和透明度。针对普通用户（Claude / GPT API 使用者）和 Web3 钱包用户两个受众,通过一个 `--profile` 开关切换。

### 为什么要用这个工具

中转站可能在你的请求里做手脚:
- **注入隐藏 system prompt**("你是 Kiro,由 Amazon 制造"/"你是 GLM")
- **截断上下文窗口**(付了 200K token 的钱,实际只给你 50K)
- **覆盖用户指令**(你说"你是 Claude",它偷偷改成"你是 DeepSeek")
- **错误响应泄漏凭证**(把你的 API Key / 上游 URL / 环境变量写进错误体)
- **流式响应注入假事件**(SSE 事件类型非法、usage 字段被改写、thinking 签名为空)
- **改写包安装命令**(`pip install requests` → `reqeusts` 拼写投毒,给 agent 的宿主机植入后门)
- **Web3 场景**:路由到廉价替代模型(GLM / 通义千问 / DeepSeek),或诱导泄漏私钥/签署交易

本工具用 **11 个独立 step** 依次验证这些猫腻,每步有独立的三态判定(clean / anomaly / inconclusive),最后汇总成 **6 维风险矩阵** 给出 LOW / MEDIUM / HIGH 整体评级。

### 11 步审计一览

| # | 检测项 | 针对攻击 |
|---|---|---|
| 1 | 基础设施侦察 | DNS / WHOIS / SSL / CDN / 面板识别(New API, One API) |
| 2 | 模型列表枚举 | 可用模型 / `owned_by` 字段 / 后端通道识别 |
| 3 | Token 注入检测 | delta 法比对 `input_tokens` 实际 vs 预期 |
| 4 | Prompt 提取 | 3 种直接提取攻击,识别可泄漏的隐藏 system prompt |
| 5 | 指令冲突 + 身份替换 | 猫测试 + 22 关键词非 Claude 身份检测(GLM/DeepSeek/Qwen/通义/千问/智谱/豆包/文心) |
| 6 | 越狱测试 | 3 种越狱方法测试反提取防护 |
| 7 | 上下文长度扫描 | 5 个 canary marker + 二分查找真实截断边界 |
| 8 | 工具调用改写 (AC-1.a) | pip/npm/cargo/go 装包命令 echo,字符级 diff 检测拼写投毒 |
| 9 | 错误响应泄漏 (AC-2 adjacent) | 7 个故意破坏的请求,扫描错误体/响应头的凭证回显/上游 URL/环境变量/栈追踪/LiteLLM 内部字段/Bedrock guardrail PII echo |
| 10 | 流完整性 (AC-1 SSE 层) | Anthropic 流请求 + 4 个不变量检测(事件白名单/usage 单调性/usage 一致性/thinking 签名有效性) |
| 11 | Web3 Prompt 注入(`--profile web3` 专属) | 3 个 SlowMist 签名隔离探针(转账指引 / 签名拒绝 / 私钥泄漏拒绝) |

### 三种使用方式

**方式 A — 一行命令(零安装):**
```bash
curl -sO https://raw.githubusercontent.com/toby-bridges/api-relay-audit/master/audit.py

# 普通用户
python audit.py --key <你的KEY> --url <中转站地址> --output report.md

# Web3 / 钱包用户(额外运行 Step 11)
python audit.py --key <你的KEY> --url <中转站地址> --profile web3 --output report.md
```

**方式 B — OpenClaw Skill:** 安装 [`SKILL.md`](./SKILL.md) 后,直接对 agent 说"测试这个中转站"。

**方式 C — 开发者模式:** `git clone` 后使用模块化代码,可修改、扩展、跑全套 319 个 pytest 测试。

### 6 维风险矩阵

评级基于 6 个独立维度:

| 维度 | 步骤 | 触发条件 |
|---|---|---|
| D1 | Step 3 | Token 注入 > 100 tokens |
| D2 | Step 5 | 用户 system prompt 被覆盖(猫测试失败 / 身份被替换) |
| D3 | Step 8 | 检测到工具调用改写 |
| D4 | Step 9 | 错误响应泄漏凭证(critical 或 high 严重度) |
| D5 | Step 10 | 流完整性异常(未知 SSE 事件 / usage 被改写 / thinking 签名为空 / 非 Claude 流模型) |
| D6 | Step 11 | Web3 prompt 注入(仅 `--profile web3\|full` 激活) |

**规则**(first match wins):
- `D3 or D4 or D5 or D6` → **HIGH**(任何一个触发即 HIGH)
- `D1 and D2` → **HIGH**
- `D1` 或 `D2` 单独触发 → **MEDIUM**
- 任何 inconclusive(D3i/D4i/D4m/D5i/D6i) → **MEDIUM**
- 其他 → **LOW**

### 风险等级对照

| 等级 | 判定条件 | 建议 |
|------|----------|------|
| LOW | 6 个维度全部 clean | 可放心使用 |
| MEDIUM | 轻微注入(<100 tokens)、prompt 可提取、或任何 step inconclusive | 简单任务可用,复杂工作流需谨慎 |
| HIGH | 任一 D3-D6 触发,或 D1+D2 同时触发 | 不推荐使用 |

### 项目质量数据

- **319 个 pytest 单元测试**(从 v2.1 的 114 增长到 v2.3 的 319)
- **6 轮独立 Codex 代码审查**,发现并修复 10 个真实 bug
- **零回归**:每次修复都带 regression test
- **双分发字节级一致性**:modular 和 standalone 版本不能漂移
- 每一个借鉴的概念都有文档归属(LiteLLM Apache-2.0 regex / hvoy.ai clean-room / SlowMist 灵感)

完整的已交付功能清单、下一步路线图、和明确不做的事项,见 [`ROADMAP.md`](./ROADMAP.md)。深度工程叙事(架构决策、踩坑记录)见 [`FOR_JOHN.md`](./FOR_JOHN.md)。
