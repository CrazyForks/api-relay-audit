# api-relay-audit Roadmap

Living document tracking completed work, near-term candidates, medium-term
ideas, explicitly deferred backlog, and the explicit "not-doing" list. Each
item has a short rationale so future contributors (including future
iterations of the author) can quickly reconstruct why a thing is or is not
on the list.

**Last updated**: 2026-04-11 (session ending at commit `12959f3`)

**Threat model anchor**: Liu et al., *Your Agent Is Mine: Measuring
Malicious Intermediary Attacks on the LLM Supply Chain*, arXiv:2604.08407.
Detection concepts cross-referenced with SlowMist OpenClaw Security
Practice Guide and hvoy.ai `zzsting88/relayAPI` `claude_detector.py`.

---

## ✅ Shipped

### v2.1 and earlier (pre-session baseline)
- Steps 1-7: infrastructure recon / model list / token injection via delta
  method / prompt extraction / instruction conflict / jailbreak / context
  length scan
- Step 8: AC-1.a tool-call package substitution (pip / npm / cargo / go
  echo probes with character-level diff)
- 3D risk matrix (D1 injection / D2 override / D3 substitution)
- Dual-distribution: `scripts/audit.py` + `api_relay_audit/*.py` modular,
  `audit.py` standalone curl-only single-file

### v2.2 + v2.3 + v1.7.3 (shipped 2026-04-11, 12 commits in one session)
- **Step 9 — Error Response Header Leakage (AC-2 adjacent)**: 7 deterministic
  broken requests + scan for credential echo / upstream URLs / env vars /
  FS paths / stack traces / LiteLLM internal fields / Bedrock guardrail PII
  echoes. Sourced from 8 verified LiteLLM GitHub issue bug reports.
- **Step 10 — Stream Integrity (AC-1 SSE-level)**: Anthropic streaming
  probe + 4 invariants (SSE event whitelist / `output_tokens` monotonicity /
  `input_tokens` consistency / thinking signature validity) + stream model
  identity check. Concept verified against hvoy.ai `claude_detector.py`,
  clean-room reimplementation with tri-state verdicts instead of their
  0-100 score.
- **Step 11 — Web3 Prompt Injection (profile=web3|full)**: 3 probes
  targeting SlowMist signature isolation (transfer guidance / sign refusal
  / private key refusal). Safe-priority classifier with hard-injection
  override for contradictory responses.
- **Non-Claude identity detection**: 22-keyword tuple with two-tier
  matching (strict keywords require identity anchor phrases; lax keywords
  use word-boundary + non-letter lookahead). Catches Chinese-market
  substitutes: GLM / DeepSeek / Qwen / MiniMax / Grok / GPT / ERNIE /
  Doubao / Moonshot / Kimi + Chinese brand names (通义/千问/智谱/豆包/
  文心/月之暗面). Eliminates residual "I am Claude, not GPT" false
  positive.
- **`--profile {general,web3,full}` flag**: runtime audience selector
  instead of git branch split. Web3 users opt in; general users see no
  change. Preserves dual-distribution, test suite, memory, and single-
  source-of-truth invariants that branches would break.
- **6D risk matrix** (D1/D2/D3/D3i/D4/D4m/D4i/D5/D5i/D6/D6i) with
  character-identical parity between modular and standalone audit.py.
- **10 Codex-review bugs fixed** across 6 independent review rounds
  (2 MEDIUM + 1 LOW + 1 NIT + 1 MEDIUM + 1 MEDIUM + 1 LOW + 1 MEDIUM +
  2 LOW). Every fix has a regression test.
- **319 pytest tests** (from 114 baseline, +205 new, zero regressions)
- **11 CLI flags** and 3 profile choices
- FOR_JOHN.md diary chapter, memory files updated, full push to
  `origin/master`

---

## 🔜 Near-term candidates (next 1-2 sessions)

Pick one of these to start the next session. Each is scoped to fit in a
single session, has a clear spec, and does not require new infrastructure.

### 1. `--transparent-log <path>` flag (arXiv §7.3 forensic log)
**Status**: spec'd in `plans/fluttering-spinning-origami.md`, not started
**Scope**: ~150 LOC new module + ~15 tests + integration in `APIClient`
**Why**: the paper's §7.3 recommendation — an append-only JSONL log of
every request with redacted body, router URL, TLS metadata, and SHA-256
of raw response bytes. **Hash only, not body** — matches paper verbatim,
keeps entries ≤1.5 KB. Usable as forensic scoping data after a breach is
discovered.
**Dependencies**: none. Pure local file I/O. Orthogonal to all detection
logic. Does not need a test key or live relay.
**Recommended as next-session starter**.

### 2. Step 12: Crypto Address Substitution (profile=web3|full)
**Status**: spec'd, deferred from original v3 PR 2
**Scope**: ~180 LOC new module + ~30 tests
**Why**: arXiv §5.2 reports a real case of a relay draining an ETH
private key. Probe set: ETH USDT contract / BTC Satoshi genesis /
SOL Token Program / ERC-20 transfer calldata / BTC bech32 address.
**Strict byte-level classifier** — NO case folding, because ETH
addresses use EIP-55 checksum mixed case.
**Dependencies**: none. Byte-level string comparison, no crypto libs.
**Cost of deferring further**: low — no new adversarial case has been
reported since the original paper.

### 3. Identity anchor residual edges (v1.7.4)
**Status**: 2 known residuals from Codex Round 6, documented as LOW
**Scope**: ~30 LOC + 5 tests
**Why**:
- **Chinese no-whitespace case**: `"我是GPT-5"` (no space between anchor
  and keyword) currently misses because the regex requires `\s+`.
- **>4 filler words case**: `"I'm an advanced conversational AI system
  fine-tuned by OpenAI called GPT-5"` has 6 filler words, exceeds the
  `{0,4}` cap.
**Fix options**: add a separate CJK-anchor pattern that allows zero
whitespace before the keyword; raise the filler cap to 6 or 8.
**Risk**: minor — both cases are rare in 200-token identity-test
responses.

### 4. Local one-api Docker real-world validation
**Status**: not a coding task — ops / validation exercise
**Scope**: 30-60 minutes Docker setup + audit run + write-up
**Why**: generate the first real "before/after" detection rate data by
running the tool against a clean local one-api deployment. Confirms that
the 11-step pipeline does not false-positive on a legitimate relay.
**Dependencies**: Docker + a valid upstream API key. `one-api` source
is publicly available at `github.com/songquanpeng/one-api`.
**Output**: a `reports/one-api-clean-baseline.md` file plus a diary entry
in `FOR_JOHN.md` documenting what Step 9 actually caught.

### 5. MistTrack AML integration (profile=web3|full, optional)
**Status**: sketched in SlowMist OpenClaw Practice Guide, not started
**Scope**: ~100 LOC adapter + external API dependency
**Why**: SlowMist's "Cross-Skill Pre-flight Check" pattern — when an
agent is about to make a high-value crypto action, call MistTrack for an
AML risk score. Score ≥ 90 → hard abort. Integrates well with our
`--profile web3` flag.
**Dependencies**: MistTrack API key or public endpoint. Breaks the
zero-dep invariant for standalone `audit.py`. Should probably be
modular-only, with `--profile full` gate.
**Cost of deferring**: low — requires external infrastructure setup.

---

## 🛠 Medium-term ideas (1-3 month horizon)

### 6. Full AC-1 tool_call support (as opposed to AC-1.a text echo)
**Status**: backlog item from Step 8
**Scope**: ~150 LOC — `APIClient.tool_call()` method + structured
tool_call payload inspection + matching probe set
**Why**: Step 8 currently catches AC-1.a (typosquat on plain text echoes)
via text-level comparison. A more specific attack — rewriting the
`tool_calls` JSON payload but leaving plain text alone — is not caught.
Paper §4.2.1 notes: "the compromised dependency is cached locally and
re-imported across future sessions, giving the attacker a durable
supply-chain foothold."
**Cost vs benefit**: marginal coverage uplift over AC-1.a (all observed
wild samples were AC-1.a). Defer until the first wild AC-1 case is
reported.

### 7. Schema deviation anomaly detection (paper §7.2)
**Status**: paper lists it as a detection dimension; we don't implement
**Scope**: unknown — would need design work. Paper §7.2 Table 10 reports
~10% contribution to AC-1.a detection at 6.7% FPR budget, 0% at 1% FPR
budget.
**Why not**: low marginal value — our byte-level diff in Step 8 is
strictly better on AC-1.a, and the architectural complexity of adding a
schema-deviation feature to both distributions is high. Paper authors
themselves flagged this as the weakest of their three defenses.
**Decision**: defer indefinitely unless a new attack class needs it.

### 8. JA3 fingerprint clustering
**Status**: mentioned in paper §7.3 (6 JA3 fingerprints observed on 147
IPs, 40k unauthorized access attempts)
**Scope**: client-side JA3 fingerprinting + server-side collection +
corpus-level clustering
**Why not yet**: single-session value is low. JA3 clustering becomes
valuable after the audit corpus reaches ≥100 distinct relay endpoints.
We currently have 0 in our corpus (users run the tool ad-hoc). Revisit
after ~6 months of field use and corpus growth.

### 9. Structured audit corpus from hvoy.ai leaderboard
**Status**: hvoy.ai `/APIreview.html` lists 40+ real Chinese relay
endpoints with CNY pricing and推荐/中性/不推荐 ratings
**Scope**: ops + data pipeline: scrape or manually collect the list,
request consent from relay operators, run api-relay-audit against each,
compile a `reports/corpus-2026-Qx.md` document
**Why**: independent validation — our tool's findings should be compared
against hvoy.ai's recommendations and any divergence explained. Also
gives us JA3 data (see item 8) if we collect client-side TLS fingerprints
during the audit runs.
**Legal consideration**: some of the listed relays may have ToS that
prohibit audit probing. Need consent per-relay.
**Cost**: high — multi-session ops work.

### 10. English-first README + blog-post announcement
**Status**: current README has English intro + 中文说明 section
**Scope**: polish pass + a 500-word X/Twitter announcement thread
**Why**: broader visibility after the Codex review loop gave us a
credible quality story ("10 bugs found and fixed across 6 reviews, all
with regression tests"). The 319-test count is a marketable data point.
**When**: after item 1 or 4 — the tool should have one more
differentiating feature before the announcement.

---

## 🤔 Long-term / uncertain

### 11. AC-2 active webhook canary
**Status**: paper describes this as the highest-confidence AC-2 signal
**Blocker**: requires a publicly reachable HTTPS endpoint to receive
beacon requests. Breaks the zero-dep invariant. Needs domain name,
HTTPS cert, webhook receiver service.
**When**: if/when api-relay-audit gets a hosted component.

### 12. Full AC-1.b conditional-delivery detection
**Status**: paper §4.2.2 lists 5 theoretical trigger families (content
keyword, user fingerprint, time windows, request count, tool name)
**Blocker**: paper itself concludes "finite black-box auditing is
fundamentally inadequate for conditional delivery." We can probe some
families (Step 8 + `--warmup` partially covers request-count gating),
but complete coverage requires many-round or long-running audits.
**Decision**: accept this as an out-of-scope attack class. Document in
README limitations.

### 13. Hosted web dashboard (hvoy.ai-style)
**Status**: hvoy.ai has a React/Vite dashboard that makes the tool
approachable to non-developers
**Blocker**: requires separate web app maintenance, API backend, auth.
Changes the product from "one-curl-download" to "hosted service".
**Decision**: out of scope for the CLI project. If demand emerges, spin
off a separate repo.

### 14. Claude Code CLI header impersonation
**Status**: observed in hvoy.ai's `get_headers` function (impersonates
`claude-cli/2.0.76` + all x-stainless-* headers)
**Why not port**: would make our requests indistinguishable from their
tool — no differentiation benefit. Also, impersonating a specific CLI
version is brittle (breaks when Claude Code bumps its version).
**Decision**: permanently out of scope.

---

## 🚫 Explicitly NOT doing (and why)

These were evaluated and deliberately dropped. They are listed here so
future contributors don't re-consider them without new information.

| Item | Why not |
|---|---|
| Token accounting audit (exact token counting) | Paper out of scope; no clean offline tokenizer; character-ratio heuristic too noisy; breaks zero-dep invariant if `tiktoken` added. |
| Knowledge cutoff probe (hvoy.ai dimension 1) | Author of hvoy.ai acknowledges it is trivially defeated by a relay hard-coding "May 2025" in system prompts. 50% of their score is wasted. |
| hvoy.ai 0-100 numeric scoring | We use 6D boolean risk matrix for clearer downstream decisions. Numeric thresholds need recalibration every model generation. |
| Copy hvoy.ai's `"null"` text block body fingerprint | Unclear purpose in upstream source; would make our requests indistinguishable from theirs (no benefit). |
| 4-tier risk scale (adding CRITICAL) | Requires Reporter class refactor; dashboard has downstream consumers; current LOW/MEDIUM/HIGH covers the action space. |
| Git branch split (main + web3) | `--profile` runtime flag is strictly better: one codebase, one test suite, one distribution, single-source-of-truth memory. Branches would double maintenance cost and break `test_dual_distribution_parity`. |
| Auto-detection of OpenAI streaming | Step 10 is Anthropic-only by design; OpenAI SSE schema differs. A Chinese relay that only speaks OpenAI format is correctly reported as "inconclusive" on Step 10, not "clean". |

---

## 📐 Architectural invariants (must-preserve)

When adding any new feature, verify these hold before committing:

1. **Dual-distribution parity** — `test_risk_matrix_character_identical`
   must stay green. Any risk matrix change must be mirrored byte-for-byte
   into `audit.py` standalone. Add parity tests for any new shared
   constants (see `TestWeb3MarkerParity` as an example).
2. **Zero-dependency standalone** — `audit.py` must run on vanilla
   Python 3.7+ with only `curl` available. No new pip dependencies in
   the standalone distribution. New third-party libs go in
   `api_relay_audit/*` modular only.
3. **Profile gating** — any new detection step that only serves a subset
   of users (e.g. Web3-specific) must be gated by `--profile web3|full`
   and default to **off** under `--profile general`.
4. **Risk matrix monotonic** — a new dimension can only add to the risk
   matrix, never weaken an existing determination. New dimensions go
   into HIGH or MEDIUM branches, never LOW.
5. **Memory-grounded decisions** — before adding a feature, check
   `~/.claude/projects/C--Users-john-Downloads-api-relay-audit/memory/`
   for prior decisions on the same topic. Especially `project_competitive_
   landscape.md` (so we don't re-invent hvoy.ai features) and
   `reference_litellm_secret_regex.md` (so Step 9 patterns stay in sync
   with LiteLLM's issue tracker).
6. **Codex review loop** — any feature PR ≥200 LOC or adding a new
   detection step should get at least 2 rounds of independent Codex
   review. The review loop found 10 real bugs in this session that would
   otherwise have shipped; the cost (~2-5 min per round) is trivial
   compared to the false-negative risk.
7. **Attribution for ported concepts** — when porting from hvoy.ai,
   SlowMist, LiteLLM, or one-api, add clear docstring attribution
   ("concept inspired by X, clean-room reimplementation"). License
   matters: LiteLLM is Apache-2.0 (can port code verbatim); hvoy.ai has
   no LICENSE (must be clean-room); SlowMist docs are narrative (ideas,
   not code).

---

## 🧭 How to use this roadmap

**Starting a new session**:
1. Read the top "Shipped" section to know current state
2. Read "Near-term candidates" — pick one based on available time
3. If the session is short (< 1 hour), pick items 1, 3, or 4. If longer,
   pick item 2 or 5.

**Completing a feature**:
1. Move it from "Near-term" to "Shipped" with the commit hash
2. Add any sub-items that got deferred to the appropriate section
3. If the decision changed what was previously "explicitly not doing",
   update the reason or remove it

**Proposing a new feature**:
1. First check the "Explicitly NOT doing" table — if it's listed, do not
   re-propose without new information
2. Check "Architectural invariants" — does the feature break any?
3. Draft the item in the appropriate time horizon section with a
   rationale and dependencies
4. Run it through Codex review methodology during implementation
