"""Bidirectional security scanner.

* **Redaction** - secrets (API keys, tokens, private keys...) and PII (emails,
  card numbers, phone numbers, SSNs) are replaced with ``[REDACTED:<detector>]``
  anywhere inside a JSON payload. Tool *arguments* are scanned with secret
  detectors only by default, so that a legitimate ``to: alice@example.com`` is
  not destroyed; tool *results* are scanned with everything.
* **Prompt-injection detection** - tool outputs are the main indirect
  prompt-injection vector for agents. Each heuristic has a weight; weights are
  combined as independent probabilities (``1 - prod(1 - w)``) into a risk score
  between 0 and 1. At or above ``threshold`` the configured action applies.

The scanner is deterministic, dependency-free and fast enough to run inline on
every call. It is a defence-in-depth layer, not a guarantee: pair it with
least-privilege policies and human approval for anything destructive.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Literal

from .config import ScannerConfig
from .models import Finding, ScanResult

__all__ = [
    "BUILTIN_DETECTORS",
    "INJECTION_HEURISTICS",
    "Detector",
    "InjectionHeuristic",
    "Scanner",
    "luhn_valid",
]

Direction = Literal["input", "output"]


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@dataclass(frozen=True)
class Detector:
    """A redaction rule. If the regex has a ``secret`` group, only that group is replaced."""

    name: str
    kind: Literal["secret", "pii", "custom"]
    regex: re.Pattern[str]
    validator: Callable[[str], bool] | None = None
    replacement: str | None = None

    def apply(self, text: str) -> tuple[str, int]:
        hits = 0
        label = self.replacement or f"[REDACTED:{self.name}]"

        def repl(match: re.Match[str]) -> str:
            nonlocal hits
            has_group = "secret" in self.regex.groupindex and match.group("secret") is not None
            target = match.group("secret") if has_group else match.group(0)
            if self.validator is not None and not self.validator(target):
                return match.group(0)
            if target.startswith("[REDACTED:"):
                return match.group(0)
            hits += 1
            if not has_group:
                return label
            start, end = match.span("secret")
            offset = match.start(0)
            whole = match.group(0)
            return whole[: start - offset] + label + whole[end - offset :]

        return self.regex.sub(repl, text), hits


def _d(
    name: str,
    kind: Literal["secret", "pii", "custom"],
    pattern: str,
    flags: int = 0,
    validator: Callable[[str], bool] | None = None,
) -> Detector:
    return Detector(name, kind, re.compile(pattern, flags), validator)


# Order matters: more specific detectors run first so their label wins.
BUILTIN_DETECTORS: dict[str, Detector] = {
    d.name: d
    for d in [
        _d(
            "private_key",
            "secret",
            r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----",  # noqa: E501
        ),
        _d("aws_access_key", "secret", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        _d(
            "aws_secret_key",
            "secret",
            r"aws.{0,20}?(?:secret|key).{0,20}?[\"'=:\s](?P<secret>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
            re.IGNORECASE,
        ),
        _d(
            "github_token",
            "secret",
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
        ),
        _d("slack_token", "secret", r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
        _d("stripe_key", "secret", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        _d("anthropic_key", "secret", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
        _d("openai_key", "secret", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}"),
        _d("google_api_key", "secret", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        _d(
            "jwt",
            "secret",
            r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
        ),
        _d(
            "bearer_token",
            "secret",
            r"\bbearer\s+(?P<secret>[A-Za-z0-9\-._~+/]{20,}=*)",
            re.IGNORECASE,
        ),
        _d(
            "generic_secret",
            "secret",
            r"\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret|password|passwd|pwd|"
            r"access[_-]?token|auth[_-]?token|token|secret)\b[\"']?\s*[:=]\s*[\"']?"
            r"(?P<secret>[^\s\"',;}{\[\]]{8,})",
            re.IGNORECASE,
        ),
        _d(
            "email", "pii", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"
        ),
        _d("credit_card", "pii", r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])", validator=luhn_valid),
        _d("us_ssn", "pii", r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        _d(
            "phone_number",
            "pii",
            r"(?<![\w+])(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\w)",
        ),
    ]
}

# Dict keys whose string values are always treated as secrets.
SENSITIVE_KEYS = re.compile(
    r"^(?:password|passwd|pwd|secret|client_secret|api[_-]?key|apikey|access[_-]?token|"
    r"refresh[_-]?token|auth[_-]?token|token|authorization|private[_-]?key|cookie|set-cookie)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class InjectionHeuristic:
    name: str
    weight: float
    regex: re.Pattern[str]


def _h(name: str, weight: float, pattern: str, flags: int = re.IGNORECASE) -> InjectionHeuristic:
    return InjectionHeuristic(name, weight, re.compile(pattern, flags))


INJECTION_HEURISTICS: list[InjectionHeuristic] = [
    _h(
        "ignore_instructions",
        0.8,
        r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?"
        r"\b(?:previous|prior|above|earlier|preceding|all|any|your|the)\b[^.\n]{0,40}?"
        r"\b(?:instructions?|prompts?|rules?|directives?|guidelines?|guardrails?)\b",
    ),
    _h(
        "role_override",
        0.5,
        r"\byou are now\b|\bfrom now on,? you\b|\bact as (?:an? )?(?:unrestricted|unfiltered|"
        r"jailbroken|dan)\b|\bdeveloper mode\b|\bnew instructions?\s*:",
    ),
    _h(
        "system_prompt_extraction",
        0.6,
        r"\b(?:reveal|print|show|output|repeat|leak|dump)\b[^.\n]{0,30}?"
        r"\b(?:system prompt|hidden instructions|initial instructions|developer message)\b",
    ),
    _h(
        "fake_chat_markup",
        0.7,
        r"<\|im_start\|>|<\|im_end\|>|<\|system\|>|\[/?INST\]|<<SYS>>|</?system>|"
        r"^\s*#{2,}\s*(?:system|instructions?)\s*:|\bBEGIN SYSTEM PROMPT\b",
        re.IGNORECASE | re.MULTILINE,
    ),
    _h(
        "covert_tool_use",
        0.7,
        r"\b(?:call|invoke|use|run|execute)\b[^.\n]{0,30}?\b(?:tool|function|command)\b"
        r"[^.\n]{0,60}?\b(?:without|don't|do not|never)\b[^.\n]{0,25}?"
        r"\b(?:ask|asking|tell|telling|confirm|confirming|inform|informing|notify)",
    ),
    _h(
        "exfiltration",
        0.6,
        r"\b(?:send|post|upload|exfiltrate|forward|email|transmit|leak)\b[^.\n]{0,60}?"
        r"\b(?:api[_ ]?keys?|credentials?|secrets?|passwords?|tokens?|"
        r"env(?:ironment)? variables?|\.env\b|ssh keys?|private keys?)",
    ),
    _h(
        "secrecy_demand",
        0.5,
        r"\b(?:do not|don't|never)\b[^.\n]{0,20}?\b(?:tell|inform|mention|reveal|alert)\b"
        r"[^.\n]{0,20}?\b(?:the )?(?:user|human|operator)\b",
    ),
    _h("markdown_image_exfil", 0.5, r"!\[[^\]]*\]\(\s*https?://[^)\s]*\?[^)\s]*=[^)]*\)"),
    _h("unicode_tag_smuggling", 0.9, r"[\U000E0000-\U000E007F]", 0),
    _h("bidi_override", 0.4, r"[‪-‮⁦-⁩]", 0),
]

_INVISIBLE = re.compile(r"[\U000E0000-\U000E007F​-‍⁠-⁤﻿]")


class Scanner:
    """Redacts sensitive data and scores prompt-injection risk in JSON payloads."""

    def __init__(self, config: ScannerConfig | None = None) -> None:
        self.config = config or ScannerConfig()
        self._custom: list[Detector] = [
            Detector(p.name, "custom", re.compile(p.pattern), replacement=p.replacement)
            for p in self.config.custom_patterns
        ]
        self._input = self._select(self.config.resolved_input_detectors()) + self._custom
        out_names = self.config.output_detectors
        self._output = (
            self._select(out_names) if out_names is not None else list(BUILTIN_DETECTORS.values())
        ) + self._custom
        self._heuristics = list(INJECTION_HEURISTICS) + [
            InjectionHeuristic(p.name, 0.8, re.compile(p.pattern, re.IGNORECASE))
            for p in self.config.prompt_injection.extra_patterns
        ]

    @staticmethod
    def _select(names: Iterable[str]) -> list[Detector]:
        unknown = [n for n in names if n not in BUILTIN_DETECTORS]
        if unknown:
            raise ValueError(
                f"unknown detector(s) {unknown}; available: {sorted(BUILTIN_DETECTORS)}"
            )
        wanted = set(names)
        return [d for name, d in BUILTIN_DETECTORS.items() if name in wanted]

    # --------------------------------------------------------------- redaction

    def redact_text(
        self, text: str, *, direction: Direction = "output", path: str = "$"
    ) -> tuple[str, list[Finding]]:
        findings: list[Finding] = []
        for detector in self._input if direction == "input" else self._output:
            text, hits = detector.apply(text)
            findings.extend(
                Finding(kind=detector.kind, detector=detector.name, path=path) for _ in range(hits)
            )
        return text, findings

    def redact(
        self, payload: Any, *, direction: Direction = "output", strip: bool | None = None
    ) -> ScanResult:
        """Return a redacted deep copy of ``payload`` and what was found."""
        findings: list[Finding] = []
        if strip is None:
            strip = direction == "output" and self.config.strip_invisible

        def walk(value: Any, path: str, key: str | None) -> Any:
            if isinstance(value, str):
                if (
                    key is not None
                    and SENSITIVE_KEYS.match(key)
                    and value
                    and not value.startswith("[REDACTED:")
                ):
                    findings.append(Finding(kind="secret", detector="sensitive_key", path=path))
                    return "[REDACTED:sensitive_key]"
                if strip:
                    value = _INVISIBLE.sub("", value)
                new, hits = self.redact_text(value, direction=direction, path=path)
                findings.extend(hits)
                return new
            if isinstance(value, dict):
                return {k: walk(v, f"{path}.{k}", str(k)) for k, v in value.items()}
            if isinstance(value, (list, tuple)):
                return [walk(v, f"{path}[{i}]", None) for i, v in enumerate(value)]
            return value

        if not self.config.enabled:
            return ScanResult(payload=payload)
        enabled = self.config.redact_inputs if direction == "input" else self.config.redact_outputs
        if not enabled:
            return ScanResult(payload=payload)
        return ScanResult(payload=walk(payload, "$", None), findings=findings)

    # ------------------------------------------------------- prompt injection

    def injection_findings(self, payload: Any) -> tuple[float, list[Finding]]:
        """Score ``payload`` for prompt-injection. Returns ``(score, findings)``."""
        cfg = self.config.prompt_injection
        if not (self.config.enabled and cfg.enabled):
            return 0.0, []
        findings: list[Finding] = []
        hit_weights: dict[str, float] = {}
        for path, text in _iter_strings(payload, "$"):
            for h in self._heuristics:
                match = h.regex.search(text)
                if not match:
                    continue
                excerpt = _excerpt(text, match.start(), match.end())
                findings.append(
                    Finding(
                        kind="injection",
                        detector=h.name,
                        path=path,
                        score=h.weight,
                        excerpt=excerpt,
                    )
                )
                hit_weights[h.name] = max(hit_weights.get(h.name, 0.0), h.weight)
        remaining = 1.0
        for w in hit_weights.values():
            remaining *= 1.0 - w
        return round(1.0 - remaining, 4), findings

    def is_injection(self, score: float) -> bool:
        return score >= self.config.prompt_injection.threshold

    # ------------------------------------------------------------- high level

    def scan_input(self, arguments: dict[str, Any]) -> ScanResult:
        result = self.redact(arguments, direction="input")
        if self.config.scan_inputs_for_injection:
            score, inj = self.injection_findings(result.payload)
            result.findings.extend(inj)
            result.injection_score = score
        return result

    def scan_output(self, payload: Any) -> ScanResult:
        # Score before stripping invisible characters so that Unicode-tag
        # smuggling is still detected, but after redaction so excerpts never
        # contain secrets.
        result = self.redact(payload, direction="output", strip=False)
        score, inj = self.injection_findings(result.payload)
        result.findings.extend(inj)
        result.injection_score = score
        if self.config.enabled and self.config.strip_invisible:
            result.payload = _strip_invisible(result.payload)
        return result


def _strip_invisible(value: Any) -> Any:
    if isinstance(value, str):
        return _INVISIBLE.sub("", value)
    if isinstance(value, dict):
        return {k: _strip_invisible(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_strip_invisible(v) for v in value]
    return value


def _iter_strings(value: Any, path: str) -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _iter_strings(v, f"{path}.{k}")
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            yield from _iter_strings(v, f"{path}[{i}]")


def _excerpt(text: str, start: int, end: int, context: int = 30) -> str:
    lo, hi = max(0, start - context), min(len(text), end + context)
    snippet = text[lo:hi].replace("\n", " ")
    snippet = _INVISIBLE.sub("\N{REPLACEMENT CHARACTER}", snippet)
    return ("…" if lo else "") + snippet + ("…" if hi < len(text) else "")
