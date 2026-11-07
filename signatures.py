"""MCP decoy signatures — a reusable, dependency-free defensive artifact.

This is the published form of the deception classifier: a small set of named,
explainable signatures plus an `evaluate()` function any scanner or incident
responder can call on a single host. It takes a *normalized observation* (not the
census DB schema), so it is decoupled from how the data was gathered.

Everything is stdlib-only and side-effect-free. The signatures are also emitted as
`signatures.json` (machine-readable) and documented in `SIGNATURES.md`.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

_APPLIANCE_RE = re.compile(
    r"\b(vpn|router|firewall|switch|gateway|camera|dvr|nvr|nas|modem|printer|"
    r"access point|sd-wan|wireless|voip|pbx|scada|plc|thermostat|webcam)\b",
    re.I,
)
_MCP_RE = re.compile(r"\bmcp\b|model[- ]?context[- ]?protocol", re.I)

# The published signature catalogue. Severity is advisory; `weight` feeds the score.
SIGNATURES: list[dict] = [
    {
        "id": "DECOY-TARPIT",
        "name": "Catch-all tarpit",
        "severity": "high",
        "weight": 0.6,
        "description": "Returns a tool list for any request — including a nonsense tool or "
        "method name. A real server rejects what it does not implement; a tarpit answers "
        "everything.",
    },
    {
        "id": "DECOY-UNVERIFIED-BANNER",
        "name": "MCP banner without a real handshake",
        "severity": "medium",
        "weight": 0.25,
        "description": "Advertises MCP in its banner but never completes a real "
        "initialize + tools/list handshake.",
    },
    {
        "id": "DECOY-APPLIANCE",
        "name": "Incoherent appliance banner",
        "severity": "medium",
        "weight": 0.20,
        "description": "Claims to be an MCP server while also naming a network appliance "
        "(VPN, router, camera, NAS, …). Real servers do not also advertise as hardware.",
    },
    {
        "id": "DECOY-FINGERPRINT-REUSE",
        "name": "Cross-network fingerprint reuse",
        "severity": "medium",
        "weight": 0.40,
        "description": "An identical response fingerprint replicated across many IPs and three "
        "or more networks (ASNs). A genuine server is near-unique; a mass decoy is not.",
    },
]
_BY_ID = {s["id"]: s for s in SIGNATURES}


@dataclass
class Observation:
    """Normalized input. Any field may be unknown (None); absent evidence never fires."""

    banner: str = ""                      # server / product / title text the host advertised
    handshake_ok: bool | None = None      # completed a real initialize + tools/list?
    answered_nonsense: bool | None = None # returned a tool list for a bogus request? (tarpit tell)
    fingerprint_ips: int | None = None    # distinct IPs sharing this response fingerprint
    fingerprint_asns: int | None = None   # distinct ASNs sharing it


@dataclass
class Verdict:
    is_decoy: bool
    score: float
    hits: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


def looks_mcp(banner: str) -> bool:
    return bool(_MCP_RE.search(banner or ""))


def evaluate(obs: Observation, *, decoy_at: float = 0.5) -> Verdict:
    """Score a single host against the decoy signatures.

    A host that completed a real handshake is genuine by definition and scores 0 —
    legitimate replication (a SaaS fleet) is never mistaken for a campaign.
    """
    if obs.handshake_ok:
        return Verdict(is_decoy=False, score=0.0)

    hits: list[str] = []
    reasons: list[str] = []
    score = 0.0
    mcpish = looks_mcp(obs.banner)

    if obs.answered_nonsense:
        hits.append("DECOY-TARPIT")
        reasons.append("answered a nonsense request with a tool list (catch-all tarpit)")
        score += _BY_ID["DECOY-TARPIT"]["weight"]

    if mcpish and obs.handshake_ok is False:
        hits.append("DECOY-UNVERIFIED-BANNER")
        reasons.append("advertises MCP but did not complete a real handshake")
        score += _BY_ID["DECOY-UNVERIFIED-BANNER"]["weight"]

    if mcpish and _APPLIANCE_RE.search(obs.banner or ""):
        hits.append("DECOY-APPLIANCE")
        reasons.append("claims to be an MCP server and a network appliance at once")
        score += _BY_ID["DECOY-APPLIANCE"]["weight"]

    if (obs.fingerprint_ips or 0) >= 5 and (obs.fingerprint_asns or 0) >= 3:
        hits.append("DECOY-FINGERPRINT-REUSE")
        reasons.append(
            f"same fingerprint on {obs.fingerprint_ips} IPs across {obs.fingerprint_asns} networks"
        )
        score += _BY_ID["DECOY-FINGERPRINT-REUSE"]["weight"]

    score = min(1.0, round(score, 3))
    return Verdict(is_decoy=score >= decoy_at, score=score, hits=hits, reasons=reasons)


def catalog() -> list[dict]:
    """The signature catalogue, for serialization (signatures.json)."""
    return SIGNATURES


# Convenience re-exports for callers that work with plain dicts.
def evaluate_dict(d: dict) -> dict:
    obs = Observation(**{k: d.get(k) for k in Observation.__dataclass_fields__})
    return asdict(evaluate(obs))
