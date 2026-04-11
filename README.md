# API Relay Audit

by [@li9292](https://x.com/li9292)

Security audit tool for third-party AI API relay/proxy services. Detects hidden prompt injection, prompt leakage, instruction override with non-Claude identity substitution (GLM/DeepSeek/Qwen/…), context truncation, tool-call package substitution (AC-1.a), error response header leakage (AC-2 adjacent), and SSE-level stream integrity anomalies (AC-1 streaming layer).

Threat model follows the AC-1 / AC-1.a / AC-1.b / AC-2 taxonomy from Liu et al., [*Your Agent Is Mine: Measuring Malicious Intermediary Attacks on the LLM Supply Chain*, arXiv:2604.08407](https://arxiv.org/abs/2604.08407). Stream-level detection concept sourced from [hvoy.ai](https://hvoy.ai/) / `zzsting88/relayAPI` `claude_detector.py` (verified against source 2026-04-11, clean-room reimplementation).

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

全面审计第三方 AI API 中转站（反代/转发站）的安全性、可靠性和透明度。

### v2 新增

v2 新增**第 8 步：AC-1.a 工具调用改写检测**，通过让模型逐字复述四条固定的包安装命令（pip/npm/cargo/go），按 token 对比返回文本，识别恶意中转站在返回路径上偷换包名（例如 `requests` → `reqeusts` 拼写投毒）。风险矩阵升级为三维判定——只要检测到任何一次工具调用改写，单独就会直接升级为 HIGH，无需其他指标叠加。同步新增两个 CLI 开关：`--skip-tool-substitution` 跳过第 8 步，`--warmup N` 在审计前先发 N 次无害请求，作为对 AC-1.b 请求次数门控后门的部分缓解。

### 三种使用方式

**方式 A — 一行命令（零安装）：**
```bash
curl -sO https://raw.githubusercontent.com/toby-bridges/api-relay-audit/master/audit.py
python audit.py --key <你的KEY> --url <中转站地址>
```

**方式 B — OpenClaw Skill：** 安装 [`SKILL.md`](./SKILL.md) 后，直接对 agent 说"测试这个中转站"。

**方式 C — 开发者模式：** `git clone` 后使用模块化代码，可修改、扩展、跑测试。

### 风险等级

| 等级 | 判定条件 | 建议 |
|------|----------|------|
| LOW | 无注入 + 指令正常 + 上下文完整 | 可放心使用 |
| MEDIUM | 轻微注入（<100 tokens）或 prompt 可提取 | 简单任务可用 |
| HIGH | 注入 >500 tokens 或指令被覆盖 | 不推荐使用 |
