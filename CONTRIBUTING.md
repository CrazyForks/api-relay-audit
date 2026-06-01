# Contributing

Thanks for helping improve API Relay Audit. The project is intentionally scoped:
it favors local, reproducible audit evidence over broad relay rankings or
speculative detector growth.

## Good First Contributions

Good first issues usually fit one of these shapes:

- Documentation examples that do not expose real relay domains or API keys.
- Deterministic tests for existing detector behavior.
- Clarifications that make `inconclusive` results easier to understand.
- Small fixes that keep the standalone and modular versions aligned.

Before opening a larger PR, please start with an issue that explains the
real-world behavior you observed and the exact audit step it affects.

## Development Setup

```bash
pip install httpx pytest
python3 -m pytest tests/ -v
python3 scripts/collect-metrics.py --check
```

When changing audit logic, also run:

```bash
python3 scripts/build-standalone.py --check
python3 -m pytest tests/test_dual_distribution_parity.py -v
```

## Dual Distribution Rule

This repository has two distributions:

- `audit.py`: standalone, zero-dependency user artifact.
- `api_relay_audit/` plus `scripts/`: modular development version.

If you change audit behavior in `scripts/audit.py` or `api_relay_audit/`, the
standalone `audit.py` must stay in sync. The drift checks exist to prevent users
from running a different detector than contributors test.

## Pull Request Checklist

- Keep the change focused on one behavior or document.
- Avoid publishing secrets, private traffic, or real API keys.
- Do not describe a relay as safe or unsafe without reproducible evidence.
- Preserve the distinction between `clean`, `anomaly`, and `inconclusive`.
- Update public metrics with `python3 scripts/collect-metrics.py` when the
  reported step count, test count, CLI flags, or public claims change.
- Add or update tests when behavior changes.

## Public Claims

For launch copy, comparison docs, or README claims, prefer wording that can be
verified from the current repository. If a claim depends on current external
data, rerun the relevant benchmark before using it publicly.
