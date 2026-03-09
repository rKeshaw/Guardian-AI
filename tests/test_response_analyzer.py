from __future__ import annotations

import difflib
import sys
import types
from dataclasses import dataclass, field

import pytest


@dataclass
class ProbeResult:
    status_code: int = 0
    body: str = ""
    response_time_ms: float = 0.0
    headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    @property
    def is_error(self) -> bool:
        return self.error is not None


class ProbeExecutor:
    @staticmethod
    def compute_delta(current: ProbeResult, baseline: ProbeResult | None) -> dict:
        baseline_status = baseline.status_code if baseline else 0
        baseline_body = baseline.body if baseline else ""
        baseline_length = len(baseline_body)
        baseline_time = baseline.response_time_ms if baseline else 0.0
        baseline_headers = baseline.headers if baseline else {}

        added_lines = [
            line[2:]
            for line in difflib.ndiff(baseline_body.splitlines(), current.body.splitlines())
            if line.startswith("+ ")
        ]

        return {
            "status_code": current.status_code,
            "status_changed": current.status_code != baseline_status,
            "baseline_status": baseline_status,
            "body_length": len(current.body),
            "length_delta": len(current.body) - baseline_length,
            "length_ratio": (len(current.body) / baseline_length) if baseline_length > 0 else 0.0,
            "response_time_ms": current.response_time_ms,
            "time_delta_ms": current.response_time_ms - baseline_time,
            "new_content": "\n".join(added_lines),
            "new_headers": {k: v for k, v in current.headers.items() if k not in baseline_headers},
        }


# Install a deterministic test-double module for response analyzer imports.
probing_pkg = types.ModuleType("guardian.core.probing")
probe_module = types.ModuleType("guardian.core.probing.probe_executor")
probe_module.ProbeResult = ProbeResult
probe_module.ProbeExecutor = ProbeExecutor
sys.modules["guardian.core.probing"] = probing_pkg
sys.modules["guardian.core.probing.probe_executor"] = probe_module

from guardian.core.intelligence.response_analyzer import ResponseAnalyzer


def test_status_change_detected():
    analyzer = ResponseAnalyzer()
    baseline = ProbeResult(status_code=200, body="ok", response_time_ms=100)
    current = ProbeResult(status_code=500, body="err", response_time_ms=120)

    profile = analyzer.analyze(current, baseline)

    assert profile.status_changed is True
    assert profile.baseline_status == 200


def test_length_ratio_computed():
    analyzer = ResponseAnalyzer()
    baseline = ProbeResult(status_code=200, body="a" * 1000, response_time_ms=100)
    current = ProbeResult(status_code=200, body="b" * 1500, response_time_ms=100)

    profile = analyzer.analyze(current, baseline)

    assert profile.length_ratio == 1.5


def test_time_delta_computed():
    analyzer = ResponseAnalyzer()
    baseline = ProbeResult(status_code=200, body="ok", response_time_ms=100)
    current = ProbeResult(status_code=200, body="ok", response_time_ms=5200)

    profile = analyzer.analyze(current, baseline)

    assert profile.time_delta_ms == pytest.approx(5100, abs=5)


def test_error_probe_zero_fields():
    analyzer = ResponseAnalyzer()
    current = ProbeResult(error="connection refused")

    profile = analyzer.analyze(current, None)

    assert profile.error == "connection refused"
    assert profile.body_length == 0


def test_facts_extracted_from_new_content():
    analyzer = ResponseAnalyzer()
    baseline = ProbeResult(status_code=200, body="normal page", response_time_ms=50)
    current = ProbeResult(
        status_code=200,
        body="normal page\nYou have an error in your SQL syntax near '1'' at line 1",
        response_time_ms=60,
    )

    profile = analyzer.analyze(current, baseline)

    assert any("mysql_error" in fact for fact in profile.extracted_facts)


def test_to_prompt_dict_no_raw_body():
    analyzer = ResponseAnalyzer()
    baseline = ProbeResult(status_code=200, body="line1", response_time_ms=50)
    current = ProbeResult(status_code=200, body="line1\nline2", response_time_ms=60)

    profile = analyzer.analyze(current, baseline)
    prompt = profile.to_prompt_dict()

    assert "body" not in prompt
    assert "new_content_preview" in prompt
    assert isinstance(prompt["new_content_preview"], str)
    assert len(prompt["new_content_preview"]) <= 500


def test_new_content_only_additions():
    analyzer = ResponseAnalyzer()
    baseline = ProbeResult(status_code=200, body="line1\nline2\nline3", response_time_ms=50)
    current = ProbeResult(status_code=200, body="line1\nline2\nline3\nNEWLINE", response_time_ms=60)

    profile = analyzer.analyze(current, baseline)

    assert "NEWLINE" in profile.new_content
    assert "line1" not in profile.new_content

def test_to_prompt_dict_sets_time_anomaly_true_for_large_delta():
    analyzer = ResponseAnalyzer()
    baseline = ProbeResult(status_code=200, body="ok", response_time_ms=100)
    current = ProbeResult(status_code=200, body="ok", response_time_ms=5100)

    profile = analyzer.analyze(current, baseline)
    prompt = profile.to_prompt_dict()

    assert prompt["time_anomaly"] is True


def test_to_prompt_dict_sets_time_anomaly_false_for_small_delta():
    analyzer = ResponseAnalyzer()
    baseline = ProbeResult(status_code=200, body="ok", response_time_ms=100)
    current = ProbeResult(status_code=200, body="ok", response_time_ms=600)

    profile = analyzer.analyze(current, baseline)
    prompt = profile.to_prompt_dict()

    assert prompt["time_anomaly"] is False
