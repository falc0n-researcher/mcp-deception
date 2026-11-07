# `//` The Deceptive MCP Internet

**Brief 004 — field note.** Most of what looks like an exposed Model Context Protocol server is not
one. This repo is the public slice: the finding, the open detection signatures, and a dependency-free
scanner.

![focus](https://img.shields.io/badge/focus-mcp%20deception-e85002?style=flat-square&labelColor=0b0a08)
![method](https://img.shields.io/badge/method-metadata--only-ded2c0?style=flat-square&labelColor=0b0a08)
![disclosure](https://img.shields.io/badge/disclosure-aggregate--only-6f6a61?style=flat-square&labelColor=0b0a08)

> Accepted to **Black Hat MEA**. With the conference rescheduled to **May 2027**, this shares one
> slice early — the deception measurement. The exposure census and the systemic fix are held for the
> talk.

**→ Read the brief: [the findings page](https://falc0n-researcher.github.io/mcp-deception/)**

---

### `//` the finding

The Model Context Protocol lets AI agents call real tools — read a database, move money, run a
command — so an exposed MCP server is a remote API that can do damage. Count the banners and the
number is terrifying. Speak the protocol and it collapses.

| | |
|---|---:|
| hosts advertising an MCP banner | **254,530** |
| …that complete a real handshake | **0.3%** |
| reachable MCP-relevant hosts | ~11,100 |
| genuine servers / catch-all tarpits | 837 / **6,988**  (8.3 : 1) |
| this classifier — tarpit recall / false-positive | **99.1% / 0%** |
| generic honeypot tag — tarpit recall | **0%** |
| fingerprint clusters / cross-network spoof campaigns | 343 / **40** |

Catch-all tarpits — endpoints that answer *any* request with a tool list — outnumber genuine servers
**8 to 1** among hosts that actually respond. The honeypot tag that the big internet-scan databases
ship flags **none** of them: generic honeypot detection and MCP deception are orthogonal. Every MCP
threat-intel feed built on that tag is counting ghosts.

---

### `//` what's in here

- **[`index.html`](index.html)** — the findings page (GitHub Pages), with a decoy detector that runs
  entirely in your browser.
- **[`SIGNATURES.md`](SIGNATURES.md) · [`signatures.json`](signatures.json)** — the four decoy
  signatures, documented and machine-readable.
- **[`signatures.py`](signatures.py)** — a dependency-free (stdlib-only) `evaluate()` you drop into
  any scanner. A host that completes a real handshake scores `0`.
- **[`deception_scan.py`](deception_scan.py)** — a stdlib-only CLI. Point it at one or more endpoints;
  it does a metadata-only probe and prints a verdict table.

---

### `//` run it

```bash
# score a host from what you observed — no network, pure logic
python3 -c "from signatures import Observation, evaluate; \
print(evaluate(Observation(banner='MCP Server / SSL VPN', handshake_ok=False, answered_nonsense=True)))"

# or scan live endpoints (metadata-only: initialize + tools/list, never a tool call)
python3 deception_scan.py https://example.com/mcp https://another.host/mcp
```

The scanner speaks the MCP handshake exactly as a normal client would and **never calls a tool**. It
is for checking your own servers and cleaning up measurements — not for targeting anyone.

---

### `//` method, in one breath

Four explainable signals: **catch-all behaviour** (answers a nonsense request), **cross-network
fingerprint reuse** (one response across many ASNs), an **MCP banner with no real handshake**, and an
**incoherent appliance banner** (claims MCP *and* VPN/router/camera). Validated against
handshake-verified real servers and known tarpits: 99.1% recall at 0% false-positive. A genuine
handshake means genuine — a legitimately replicated fleet is never mistaken for a campaign.

---

### `//` held for the talk

The full Black Hat MEA talk (May 2027) adds the exposure census (how many *real* servers are
unauthenticated and what their tools reach), the browser-reachable attack chain, the continuous
registry supply-chain watch, and the secure-by-default fix that closes the class at the source.

---

### `//` signals

[**falc0n.tech**](https://falc0n.tech) &nbsp;·&nbsp; [**X — @0xfa1c0n**](https://x.com/0xfa1c0n)
&nbsp;·&nbsp; [**hello@falc0n.tech**](mailto:hello@falc0n.tech)

<sub>`fa1c0n@recon ~ $` &nbsp; watching the internet · filed quietly · metadata-only, aggregate-only, responsible disclosure</sub>
