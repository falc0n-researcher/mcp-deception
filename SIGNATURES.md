# MCP decoy signatures — a defensive artifact

A small, explainable signature set for telling a genuine exposed MCP server from a honeypot, catch-all tarpit or mass banner decoy. Use `signatures.evaluate()` on a normalized observation, or read these and port them into your own scanner. Metadata-only; a host that completes a real handshake is genuine by definition and scores 0.

| id | severity | signature | what it catches |
|---|---|---|---|
| `DECOY-TARPIT` | high | Catch-all tarpit | Returns a tool list for any request — including a nonsense tool or method name. A real server rejects what it does not implement; a tarpit answers everything. |
| `DECOY-UNVERIFIED-BANNER` | medium | MCP banner without a real handshake | Advertises MCP in its banner but never completes a real initialize + tools/list handshake. |
| `DECOY-APPLIANCE` | medium | Incoherent appliance banner | Claims to be an MCP server while also naming a network appliance (VPN, router, camera, NAS, …). Real servers do not also advertise as hardware. |
| `DECOY-FINGERPRINT-REUSE` | medium | Cross-network fingerprint reuse | An identical response fingerprint replicated across many IPs and three or more networks (ASNs). A genuine server is near-unique; a mass decoy is not. |

A host scoring ≥ 0.5 across these is flagged a decoy. Validated on an internet census: recovers 99.1% of known catch-all tarpits at 0% false-positive on handshake-verified servers, where the generic honeypot tag shipped by internet-scan databases flags 0%.

_Defensive use only. Report confirmed malicious infrastructure through responsible disclosure; never name a target publicly._