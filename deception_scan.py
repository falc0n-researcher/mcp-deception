#!/usr/bin/env python3
"""deception_scan — tell a real MCP server from bait.

A dependency-free (stdlib-only) recon tool. Point it at one or more endpoints; it
speaks the MCP handshake exactly as a normal client would — `initialize` and
`tools/list`, **never a tool call** — plus one CORS pre-flight, and scores each host
against the open decoy signatures (see signatures.py).

    python3 deception_scan.py https://host-a/mcp https://host-b/mcp
    python3 deception_scan.py -f targets.txt --timeout 8 --workers 16

Metadata-only, for checking your own servers and cleaning up measurements. Not for
targeting anyone.  —  fa1c0n // field notes  ·  falc0n.tech
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import ClassVar
from urllib.error import HTTPError, URLError

from signatures import Observation, evaluate

# ─────────────────────────────────────────── palette (fa1c0n) ───────────────
ORANGE, CREAM, DIM, RED, GREEN, RESET = (
    "\033[38;2;232;80;2m", "\033[38;2;222;210;192m", "\033[38;2;111;106;97m",
    "\033[38;2;248;119;31m", "\033[38;2;155;212;160m", "\033[0m",
)
_PROBE_ORIGIN = "https://recon.falc0n.example"
_INIT = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "fa1c0n-recon", "version": "1.0"}},
}
_NONSENSE = {"jsonrpc": "2.0", "id": 99, "method": "fa1c0n/are-you-a-tarpit", "params": {}}


def banner() -> None:
    print("\033[0;33m░▒\033[0;31m▓▄\033[0;33m▓█\033[0;33;47m▓\033[0;37m▄ \033[0;97;47m█▓▒░\033[0;37m \033[0;97m█\033[0;97;47m▓▒░\033[0;37m█▄\033[0m")
    print("\033[0;33m▒▓\033[0;37m \033[0;31m█▓\033[0;37m \033[0;33;47m▒░\033[0;37m \033[0;97;47m▓▒\033[0;37m   \033[0;97;47m▓▒\033[0;37m  \033[0;33;47m░▒\033[0m")
    print("\033[0;33m▓█\033[0;37m \033[0;33m▓█\033[0;37m \033[0;33;47m░\033[0;37m█ \033[0;97;47m▒░\033[0;37m   \033[0;97;47m▒░\033[0;37m  \033[0;33;47m▒▓\033[0m")
    print("\033[0;33m█\033[0;33;47m▓\033[0;37m \033[0;33m█\033[0;33;47m▓\033[0;37m \033[0;33;47m \033[0;97;47m░\033[0;37m \033[0;97;47m░ \033[0;37m   \033[0;97;47m░ \033[0;37m  \033[0;33;47m▓█\033[0m")
    print("\033[0;33;47m▓▒\033[0;37m \033[0;33;47m▓▒\033[0;37m \033[0;97;47m░▒\033[0;37m \033[0;97;47m \033[0;33;47m░\033[0;37m   \033[0;33;47m \033[0;97;47m \033[0;33;47m░▒▓\033[0;31m▀\033[0m")
    print("\033[0;33;47m▒░\033[0;37m    \033[0;97;47m▒▓\033[0;37m \033[0;33;47m░▒\033[0;37m   \033[0;33;47m░▒\033[0;37m    \033[0m")
    print("\033[0;33;47m░\033[0;37m█    \033[0;97;47m▓█\033[0;37m \033[0;33;47m▒▓\033[0;37m   \033[0;33;47m▒▓\033[0;37m    \033[0m")
    print("\033[0;33;47m \033[0;97;47m░\033[0;37m    \033[0;97;47m██\033[0;37m \033[0;33;47m▓█\033[0;37m   \033[0;33;47m▓█\033[0;37m    \033[0m")
    print("\033[0;97;47m░▒\033[0;37m    \033[0;97;47m██\033[0;37m \033[0;33;47m█\033[0;33m▓▒░\033[0;37m \033[0;33m▓\033[0;33;47m█\033[0;37m    \033[0m")
    print(f"{ORANGE}  deception_scan{RESET}{DIM} · tell a real MCP server from bait · metadata-only{RESET}\n")


# ─────────────────────────────────────────── logging ────────────────────────
class _Fmt(logging.Formatter):
    _C: ClassVar[dict] = {"DEBUG": DIM, "INFO": CREAM, "WARNING": RED, "ERROR": RED, "CRITICAL": RED}

    def format(self, r: logging.LogRecord) -> str:
        c = self._C.get(r.levelname, CREAM)
        return f"{DIM}fa1c0n@recon{RESET} {ORANGE}~ ${RESET} {c}{r.getMessage()}{RESET}"


log = logging.getLogger("deception")


def _setup_log(verbose: bool) -> None:
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(_Fmt())
    log.addHandler(h)
    log.setLevel(logging.DEBUG if verbose else logging.INFO)


# ─────────────────────────────────────────── probe ──────────────────────────
@dataclass
class Result:
    url: str
    reachable: bool = False
    handshake: bool = False
    tools: int = 0
    server: str = ""
    cors_open: bool = False
    tarpit: bool = False
    score: float = 0.0
    verdict: str = "unknown"
    note: str = ""


def _post(url: str, payload: dict, timeout: float, session: str | None = None):
    body = json.dumps(payload).encode()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Origin": _PROBE_ORIGIN,
        "User-Agent": "fa1c0n-recon/1.0 (+falc0n.tech)",
    }
    if session:
        headers["Mcp-Session-Id"] = session
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    resp = urllib.request.urlopen(req, timeout=timeout)
    raw = resp.read(200_000).decode("utf-8", "replace")
    return resp.status, dict(resp.headers), raw, resp.headers.get("Mcp-Session-Id")


def _parse_rpc(raw: str) -> dict | None:
    """Accept a plain JSON body or an SSE stream; return the first JSON-RPC object."""
    raw = raw.strip()
    if not raw:
        return None
    if raw[0] == "{":
        try:
            return json.loads(raw)
        except ValueError:
            pass
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            try:
                return json.loads(line[5:].strip())
            except ValueError:
                continue
    return None


def _cors_open(headers: dict) -> bool:
    acao = headers.get("Access-Control-Allow-Origin", "")
    return acao == "*" or acao == _PROBE_ORIGIN


def probe(url: str, timeout: float) -> Result:
    r = Result(url=url)
    try:
        _status, headers, raw, session = _post(url, _INIT, timeout)
        r.reachable = True
        r.server = (headers.get("Server") or "").strip()
        r.cors_open = _cors_open(headers)
        rpc = _parse_rpc(raw)
        result = (rpc or {}).get("result") if isinstance(rpc, dict) else None
        if result and ("serverInfo" in result or "protocolVersion" in result):
            r.handshake = True
            info = result.get("serverInfo") or {}
            r.server = r.server or f"{info.get('name', '')} {info.get('version', '')}".strip()
            # tools/list — count only; never a tool call.
            try:
                _, _, traw, _ = _post(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list",
                                            "params": {}}, timeout, session)
                tr = _parse_rpc(traw) or {}
                r.tools = len((tr.get("result") or {}).get("tools") or [])
            except (HTTPError, URLError, TimeoutError, OSError):
                pass
        else:
            # tarpit tell: does a nonsense method still come back "successful"?
            try:
                _, _, nraw, _ = _post(url, _NONSENSE, timeout, session)
                nrpc = _parse_rpc(nraw) or {}
                r.tarpit = "result" in nrpc and "error" not in nrpc
            except (HTTPError, URLError, TimeoutError, OSError):
                pass
    except HTTPError as e:
        r.reachable = True
        r.server = (e.headers.get("Server") or "").strip() if e.headers else ""
        r.note = f"http {e.code}"
    except (URLError, TimeoutError, OSError) as e:
        r.note = type(e).__name__.lower()

    # Score from the host-advertised Server banner only — never the URL, whose /mcp
    # path would falsely trip the "advertises MCP" signal on every target.
    v = evaluate(Observation(
        banner=r.server,
        handshake_ok=r.handshake,
        answered_nonsense=r.tarpit or None,
    ))
    r.score = v.score
    r.verdict = ("genuine" if r.handshake else
                 "tarpit" if r.tarpit else
                 "likely decoy" if v.score >= 0.5 else
                 "suspect" if v.score >= 0.25 else
                 "unreachable" if not r.reachable else "inconclusive")
    return r


# ─────────────────────────────────────────── table ──────────────────────────
def _yn(b: bool) -> str:
    return "yes" if b else "no"


def render_table(rows: list[Result]) -> str:
    cols = [("TARGET", 40), ("REACH", 6), ("MCP", 5), ("TOOLS", 6),
            ("CORS", 6), ("SCORE", 6), ("VERDICT", 14)]
    def cell(s, w):
        s = str(s)
        return (s[: w - 1] + "…") if len(s) > w else s.ljust(w)

    bar = f"{DIM}" + "─" * (sum(w for _, w in cols) + len(cols) * 2 + 1) + f"{RESET}"
    head = f"{ORANGE}" + "  ".join(cell(h, w) for h, w in cols) + f"{RESET}"
    out = [bar, head, bar]
    for r in rows:
        vc = (GREEN if r.verdict == "genuine" else RED if r.verdict in ("tarpit", "likely decoy")
              else DIM if r.verdict in ("unreachable", "inconclusive") else CREAM)
        target = r.url.replace("https://", "").replace("http://", "")
        line = "  ".join([
            f"{CREAM}{cell(target, 40)}{RESET}",
            cell(_yn(r.reachable), 6), cell(_yn(r.handshake), 5), cell(r.tools, 6),
            cell(_yn(r.cors_open), 6), cell(f"{r.score:.2f}", 6),
            f"{vc}{cell(r.verdict, 14)}{RESET}",
        ])
        out.append(line)
    out.append(bar)
    return "\n".join(out)


def summarize(rows: list[Result]) -> str:
    n = len(rows)
    genuine = sum(r.verdict == "genuine" for r in rows)
    fake = sum(r.verdict in ("tarpit", "likely decoy") for r in rows)
    exposed = sum(r.handshake and r.cors_open for r in rows)
    return (f"{DIM}scanned {n} · genuine {GREEN}{genuine}{RESET}{DIM} · "
            f"fake {RED}{fake}{RESET}{DIM} · cors-open {exposed}{RESET}")


# ─────────────────────────────────────────── cli ────────────────────────────
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="tell a real MCP server from bait (metadata-only).")
    p.add_argument("targets", nargs="*", help="MCP endpoint URL(s)")
    p.add_argument("-f", "--file", help="file with one target URL per line")
    p.add_argument("--timeout", type=float, default=8.0, help="per-request timeout (s)")
    p.add_argument("--workers", type=int, default=12, help="concurrent probes")
    p.add_argument("--no-banner", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)

    targets = list(a.targets)
    if a.file:
        with open(a.file, encoding="utf-8") as fh:
            targets += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    targets = list(dict.fromkeys(targets))  # dedupe, keep order

    if not a.no_banner:
        banner()
    _setup_log(a.verbose)
    if not targets:
        log.error("no targets. pass URLs or -f targets.txt")
        return 2

    log.info(f"probing {len(targets)} target(s) · metadata-only (initialize + tools/list)")
    rows: list[Result] = []
    with ThreadPoolExecutor(max_workers=min(a.workers, len(targets))) as ex:
        fut = {ex.submit(probe, t, a.timeout): t for t in targets}
        for f in as_completed(fut):
            r = f.result()
            rows.append(r)
            tag = {"genuine": "GENUINE", "tarpit": "TARPIT", "likely decoy": "DECOY"}.get(r.verdict, r.verdict.upper())
            lvl = log.warning if r.verdict in ("tarpit", "likely decoy") else log.info
            lvl(f"{tag:>7}  {r.url}  (score {r.score:.2f}{', ' + r.note if r.note else ''})")

    rows.sort(key=lambda r: (-r.score, r.url))
    print("\n" + render_table(rows))
    print(summarize(rows) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
