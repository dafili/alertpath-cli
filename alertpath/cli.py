"""Command line interface.

Exit codes are the contract:

    0   ok           a handshake completed
    1   refused      the target answered and said no
    2   timeout      nothing answered; the probe is a suspect
    3   blackhole    AAAA silently dead while IPv4 works
    4   unresolved   the name did not resolve from this vantage

A monitor reads the code. A human reads the hint. Neither should have to parse
prose to find out whose problem it is.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from typing import List

from . import __version__, core
from .remote import probe_via

EXIT_VANTAGE_ERROR = 5


def _fmt_text(res: core.Result, verbose: bool) -> str:
    lines = []
    lines.append("%s:%d  ->  %s" % (res.target, res.port, res.verdict.upper()))
    lines.append("  vantage : %s" % res.vantage)
    lines.append("  summary : %s" % res.summary)
    if res.a_records or res.aaaa_records:
        lines.append("  A       : %s" % (", ".join(res.a_records) or "none"))
        lines.append("  AAAA    : %s" % (", ".join(res.aaaa_records) or "none"))
    if verbose or res.verdict != core.VERDICT_OK:
        for a in res.attempts:
            lines.append("  %-4s %-40s %-8s %7.0fms %s"
                         % (a.family, a.address, a.outcome,
                            a.elapsed * 1000.0, a.detail))
    if res.hint:
        lines.append("  hint    : %s" % res.hint)
    if res.error:
        lines.append("  error   : %s" % res.error)
    return "\n".join(lines)


def _fmt_compare(cmp: dict) -> str:
    lines = ["", "compare -> %s" % cmp.get("verdict", "?").upper()]
    for key in ("reached", "silent", "refused"):
        if cmp.get(key):
            lines.append("  %-8s: %s" % (key, ", ".join(cmp[key])))
    lines.append("  %s" % cmp.get("detail", ""))
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="alertpath",
        description="Check whether a TCP path is really broken, or whether the "
                    "probe is the broken thing.",
        epilog="Exit codes: 0 ok, 1 refused, 2 timeout, 3 ipv6-blackhole, "
               "4 unresolved, 5 vantage error.",
    )
    ap.add_argument("--check-host", metavar="HOST",
                    help="hostname or address to test")
    ap.add_argument("--port", type=int, default=443,
                    help="TCP port (default 443)")
    ap.add_argument("--timeout", type=float, default=3.0,
                    help="per-connect deadline in seconds (default 3.0)")
    ap.add_argument("--bind", metavar="ADDR", default=None,
                    help="source address to connect from -- a second egress on "
                         "the same host, for multi-homed or VPN setups")
    ap.add_argument("--via", metavar="[user@]host", action="append", default=[],
                    help="also measure from this ssh target (repeatable); "
                         "requires nothing installed on the remote side")
    ap.add_argument("--ssh-config", metavar="PATH", default=None,
                    help="ssh config file holding host aliases; needed when the "
                         "aliases are not in ~/.ssh/config")
    ap.add_argument("--compare", action="store_true",
                    help="with --via, report whether silence is the target or "
                         "the path")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print every attempt, not just the ones that failed")
    ap.add_argument("--version", action="version",
                    version="alertpath %s" % __version__)
    args = ap.parse_args(argv)

    if not args.check_host:
        ap.error("--check-host is required")

    host = args.check_host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    results = [core.check(host, args.port, args.timeout,
                          vantage="localhost", source=args.bind)]

    for target in args.via:
        remote = probe_via(host, target, args.port, args.timeout,
                           ssh_config=args.ssh_config)
        results.append(_from_remote(host, args.port, remote))

    cmp = core.compare(results) if len(results) > 1 else None

    if args.json:
        payload = {"results": [r.to_dict() for r in results]}
        if cmp:
            payload["compare"] = cmp
        print(json.dumps(payload, indent=1, sort_keys=False))
    else:
        print("\n".join(_fmt_text(r, args.verbose) for r in results))
        if cmp:
            print(_fmt_compare(cmp))

    # A vantage that failed to run is a measurement we do not have. It must not
    # be silently outvoted by the one that did run: "I could not ask" is not
    # "they said nothing".
    if any(r.error == "vantage-error" for r in results):
        return EXIT_VANTAGE_ERROR

    if cmp:
        verdict = cmp["verdict"]
        if verdict == "incomplete":
            return EXIT_VANTAGE_ERROR
        if verdict == "ok":
            return core.EXIT_OK
        if verdict == "path":
            return core.EXIT_TIMEOUT
        if verdict == "target":
            return core.EXIT_REFUSED
        if verdict == "target-or-shared-path":
            return core.EXIT_TIMEOUT
        return core.EXIT_TIMEOUT

    return results[0].exit_code


def _from_remote(host: str, port: int, payload: dict) -> core.Result:
    """Rebuild a local Result from the remote probe's JSON.

    Deliberately tolerant: an older remote copy may omit fields, and a missing
    field must not raise in the middle of a comparison.
    """
    res = core.Result(target=host, port=port,
                      vantage=payload.get("vantage", "remote"))
    if payload.get("verdict") == "vantage-error":
        res.verdict = core.VERDICT_MIXED
        res.summary = payload.get("summary", "remote probe failed")
        res.hint = payload.get("detail", "")
        res.error = "vantage-error"
        return res

    res.verdict = payload.get("verdict", core.VERDICT_TIMEOUT)
    res.summary = payload.get("summary", "")
    res.hint = payload.get("hint", "")
    res.a_records = (payload.get("dns") or {}).get("A", [])
    res.aaaa_records = (payload.get("dns") or {}).get("AAAA", [])
    for a in payload.get("attempts", []):
        res.attempts.append(core.Attempt(
            family=a.get("family", "?"),
            address=a.get("address", "?"),
            outcome=a.get("outcome", core.ERROR),
            elapsed=float(a.get("elapsed_ms", 0)) / 1000.0,
            detail=a.get("detail", ""),
        ))
    return res


if __name__ == "__main__":
    sys.exit(main())
