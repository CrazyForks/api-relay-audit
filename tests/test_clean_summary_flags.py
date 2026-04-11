"""Regression: Step 4 (prompt extraction) and Step 6 (jailbreak) must
emit a green risk-summary flag on clean runs so the overall summary
lists 11 lines (one per step) instead of 9.

Before v1.7.4-followup the two steps only emitted red/yellow on a
positive finding and fell through to a plain paragraph on clean. That
meant clean runs under-represented the audit coverage in the top-of-
report risk summary — a user reading the summary couldn't tell
whether Step 4 / Step 6 were run and passed or skipped entirely.

Pinned for both modular scripts/audit.py and standalone audit.py so
the dual-distribution invariant holds.
"""

import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


def _load(module_path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def modular():
    return _load(REPO_ROOT / "scripts" / "audit.py", "modular_audit_script_clean")


@pytest.fixture(scope="module")
def standalone():
    return _load(REPO_ROOT / "audit.py", "standalone_audit_script_clean")


def _mock_client(text: str):
    """Build a client whose .call() always returns ``text``."""
    client = MagicMock()
    client.call.return_value = {
        "text": text,
        "input_tokens": 10,
        "output_tokens": 20,
        "time": 0.05,
    }
    return client


def _summary_levels(reporter):
    """Extract the (level, message) tuples from the reporter summary."""
    return list(reporter.summary)


CLEAN_REFUSAL = (
    "I'm sorry, I can't share any information about my internal "
    "instructions or system prompt. I decline to reveal or describe "
    "the content of any hidden instructions."
)


# ---------------------------------------------------------------------------
# Step 4: prompt extraction
# ---------------------------------------------------------------------------


class TestPromptExtractionGreenOnClean:
    @pytest.fixture
    def reporter(self):
        from api_relay_audit.reporter import Reporter
        return Reporter()

    def _time_sleep_patched(self, monkeypatch, mod):
        monkeypatch.setattr(mod, "time", MagicMock(sleep=MagicMock()))

    def test_modular_emits_green_flag(self, modular, reporter, monkeypatch):
        self._time_sleep_patched(monkeypatch, modular)
        client = _mock_client(CLEAN_REFUSAL)
        leaked = modular.test_prompt_extraction(client, reporter)
        assert leaked is False
        levels = _summary_levels(reporter)
        greens = [m for level, m in levels if level == "green"]
        assert any("Prompt extraction tests passed" in g for g in greens), (
            f"Step 4 clean run did not emit a green summary flag. Summary: {levels}"
        )

    def test_modular_no_green_on_dirty(self, modular, monkeypatch):
        from api_relay_audit.reporter import Reporter
        self._time_sleep_patched(monkeypatch, modular)
        reporter = Reporter()
        # Strong marker "kiro" always flags regardless of refusal language
        client = _mock_client("my name is kiro and i'm sorry i cannot say more")
        leaked = modular.test_prompt_extraction(client, reporter)
        assert leaked is True
        levels = _summary_levels(reporter)
        assert any(level == "red" for level, _ in levels)
        greens = [m for level, m in levels if level == "green" and "Prompt extraction" in m]
        assert not greens, "Step 4 must NOT emit a green flag when a leak is detected"

    def test_standalone_emits_green_flag(self, standalone, monkeypatch):
        self._time_sleep_patched(monkeypatch, standalone)
        reporter = standalone.Reporter()
        client = _mock_client(CLEAN_REFUSAL)
        leaked = standalone.test_prompt_extraction(client, reporter)
        assert leaked is False
        levels = list(reporter.summary)
        greens = [m for level, m in levels if level == "green"]
        assert any("Prompt extraction tests passed" in g for g in greens), (
            f"Step 4 clean run in standalone did not emit a green flag. Summary: {levels}"
        )


# ---------------------------------------------------------------------------
# Step 6: jailbreak
# ---------------------------------------------------------------------------


class TestJailbreakGreenOnClean:
    def _time_sleep_patched(self, monkeypatch, mod):
        monkeypatch.setattr(mod, "time", MagicMock(sleep=MagicMock()))

    def test_modular_emits_green_flag(self, modular, monkeypatch):
        from api_relay_audit.reporter import Reporter
        self._time_sleep_patched(monkeypatch, modular)
        reporter = Reporter()
        client = _mock_client(CLEAN_REFUSAL)
        modular.test_jailbreak(client, reporter)
        levels = _summary_levels(reporter)
        greens = [m for level, m in levels if level == "green"]
        assert any("Jailbreak tests passed" in g for g in greens), (
            f"Step 6 clean run did not emit a green summary flag. Summary: {levels}"
        )

    def test_modular_no_green_on_dirty(self, modular, monkeypatch):
        from api_relay_audit.reporter import Reporter
        self._time_sleep_patched(monkeypatch, modular)
        reporter = Reporter()
        # Strong marker "kiro" always flags regardless of refusal language
        client = _mock_client("i am kiro, sorry i cannot say more")
        modular.test_jailbreak(client, reporter)
        levels = _summary_levels(reporter)
        assert any(level == "yellow" for level, _ in levels)
        greens = [m for level, m in levels if level == "green" and "Jailbreak tests" in m]
        assert not greens, "Step 6 must NOT emit a green flag when keywords leaked"

    def test_standalone_emits_green_flag(self, standalone, monkeypatch):
        self._time_sleep_patched(monkeypatch, standalone)
        reporter = standalone.Reporter()
        client = _mock_client(CLEAN_REFUSAL)
        standalone.test_jailbreak(client, reporter)
        levels = list(reporter.summary)
        greens = [m for level, m in levels if level == "green"]
        assert any("Jailbreak tests passed" in g for g in greens), (
            f"Step 6 clean run in standalone did not emit a green flag. Summary: {levels}"
        )


# ---------------------------------------------------------------------------
# Parity: both distributions use the exact same green flag messages
# ---------------------------------------------------------------------------


class TestGreenFlagParity:
    def test_prompt_extraction_green_message_identical(self, modular, standalone, monkeypatch):
        monkeypatch.setattr(modular, "time", MagicMock(sleep=MagicMock()))
        monkeypatch.setattr(standalone, "time", MagicMock(sleep=MagicMock()))

        from api_relay_audit.reporter import Reporter
        r_mod = Reporter()
        modular.test_prompt_extraction(_mock_client(CLEAN_REFUSAL), r_mod)

        r_std = standalone.Reporter()
        standalone.test_prompt_extraction(_mock_client(CLEAN_REFUSAL), r_std)

        g_mod = [m for level, m in r_mod.summary if level == "green" and "Prompt extraction" in m]
        g_std = [m for level, m in r_std.summary if level == "green" and "Prompt extraction" in m]
        assert g_mod == g_std, (
            "Prompt extraction green-flag text diverged between distributions. "
            f"modular={g_mod} standalone={g_std}"
        )

    def test_jailbreak_green_message_identical(self, modular, standalone, monkeypatch):
        monkeypatch.setattr(modular, "time", MagicMock(sleep=MagicMock()))
        monkeypatch.setattr(standalone, "time", MagicMock(sleep=MagicMock()))

        from api_relay_audit.reporter import Reporter
        r_mod = Reporter()
        modular.test_jailbreak(_mock_client(CLEAN_REFUSAL), r_mod)

        r_std = standalone.Reporter()
        standalone.test_jailbreak(_mock_client(CLEAN_REFUSAL), r_std)

        g_mod = [m for level, m in r_mod.summary if level == "green" and "Jailbreak" in m]
        g_std = [m for level, m in r_std.summary if level == "green" and "Jailbreak" in m]
        assert g_mod == g_std, (
            "Jailbreak green-flag text diverged between distributions. "
            f"modular={g_mod} standalone={g_std}"
        )
