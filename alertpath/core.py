"""The measurement, and the decisions that depend on it.

Two rules govern this file.

First: `refused` and `timeout` are never merged. A refused connection is an
answer from the kernel, so the target was reachable and chose not to listen on
that port. A timeout is the absence of an answer, so the path itself is a
candidate cause. Merging them is what produces a page at 3am that nobody can act
on.

Second: every verdict names the vantage point it was taken from. A probe reports
from where it stands. Its verdict is about the path it took, not about the
service, and a report that omits the vantage cannot be checked by anyone. That is
why the result carries `vantage` and why `compare()` is a first-class operation
rather than a flag bolted onto the end.
"""

from __future__ import annotations

import errno
import socket
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Outcomes. Kept as plain strings so --json output is readable without a lookup
# table, and so a log line is self-explanatory a year later.
OK = "ok"
REFUSED = "refused"
TIMEOUT = "timeout"
ERROR = "error"
NORECORD = "norecord"

# Verdicts for the whole check.
VERDICT_OK = "ok"
VERDICT_REFUSED = "refused"
VERDICT_TIMEOUT = "timeout"
VERDICT_BLACKHOLE = "ipv6-blackhole"
VERDICT_UNRESOLVED = "unresolved"
VERDICT_MIXED = "mixed"
VERDICT_PROBE_ERROR = "probe-error"

# Exit codes are part of the interface, because a monitor reads a code and not a
# sentence. A checker whose exit status cannot distinguish "target said no" from
# "nobody answered" is back to the string that started this.
EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_TIMEOUT = 2
EXIT_BLACKHOLE = 3
EXIT_UNRESOLVED = 4
EXIT_PROBE_ERROR = 5

VERDICT_EXIT = {
    VERDICT_OK: EXIT_OK,
    VERDICT_REFUSED: EXIT_REFUSED,
    VERDICT_TIMEOUT: EXIT_TIMEOUT,
    VERDICT_BLACKHOLE: EXIT_BLACKHOLE,
    VERDICT_UNRESOLVED: EXIT_UNRESOLVED,
    VERDICT_MIXED: EXIT_TIMEOUT,
    VERDICT_PROBE_ERROR: EXIT_PROBE_ERROR,
}


@dataclass
class Attempt:
    """One TCP connect, from one vantage point, to one address."""

    family: str                     # "IPv4" | "IPv6"
    address: str
    outcome: str                    # ok | refused | timeout | error
    elapsed: float
    detail: str = ""

    def to_dict(self) -> Dict:
        return {
            "family": self.family,
            "address": self.address,
            "outcome": self.outcome,
            "elapsed_ms": round(self.elapsed * 1000.0, 1),
            "detail": self.detail,
        }


@dataclass
class Result:
    """A verdict plus everything needed to distrust it."""

    target: str
    port: int
    vantage: str = "localhost"
    verdict: str = VERDICT_OK
    summary: str = ""
    hint: str = ""
    attempts: List[Attempt] = field(default_factory=list)
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    error: str = ""

    @property
    def exit_code(self) -> int:
        return VERDICT_EXIT.get(self.verdict, EXIT_TIMEOUT)

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "port": self.port,
            "vantage": self.vantage,
            "verdict": self.verdict,
            "summary": self.summary,
            "hint": self.hint,
            "exit_code": self.exit_code,
            "dns": {"A": self.a_records, "AAAA": self.aaaa_records},
            "attempts": [a.to_dict() for a in self.attempts],
            "error": self.error,
        }


# ---------------------------------------------------------------- resolution

def resolve(host: str, family: int) -> Tuple[List[str], str]:
    """Addresses for host in one family, plus why the list is empty if it is.

    "no records published" and "the lookup itself failed" mean different things:
    the first is a fact about the target's DNS, the second is a fact about this
    machine's resolver. Collapsing them would make a broken resolver look like a
    domain that does not exist.
    """
    try:
        infos = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        # EAI_NONAME / EAI_NODATA: the name has no records in this family.
        if exc.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)):
            return [], ""
        return [], "lookup failed: %s" % (exc.strerror or exc)
    except (UnicodeError, OSError) as exc:
        return [], "lookup failed: %s" % exc

    seen = set()
    out = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.add(addr)
            out.append(addr)
    return out, ""


def connect_once(address: str, family: int, port: int,
                 timeout: float, source: Optional[str] = None) -> Attempt:
    """One TCP connect attempt, classified by what the kernel did.

    The whole design rests on this distinction:
      ok      - the handshake completed
      refused - the kernel got an answer and the answer was no
      timeout - nothing answered before the deadline

    A refused connection is an answer, so the target is alive and the port is
    closed or filtered by policy. A timeout is the absence of an answer, so the
    route, the firewall, or the probe's own egress is in the frame.
    """
    label = "IPv6" if family == socket.AF_INET6 else "IPv4"
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    started = time.time()
    try:
        if source:
            sock.bind((source, 0))
        sock.connect((address, port))
        return Attempt(label, address, OK, time.time() - started, "")
    except socket.timeout:
        return Attempt(label, address, TIMEOUT, time.time() - started,
                       "no response before %gs deadline" % timeout)
    except OSError as exc:
        detail = exc.strerror or str(exc)
        # Not every OSError is an answer from the target. Only these mean the
        # network said something about the far end; EINVAL from a bad --bind, or
        # EACCES from a local policy, are facts about this invocation. Counting
        # them as "refused" would report a typo in our own flags as a target
        # that is up and declining connections.
        if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
            detail = "%s (no route in this family)" % detail
            return Attempt(label, address, REFUSED, time.time() - started, detail)
        if exc.errno in (errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED):
            return Attempt(label, address, REFUSED, time.time() - started, detail)
        return Attempt(label, address, ERROR, time.time() - started,
                       "%s (this is a local configuration problem, not a "
                       "verdict about the target)" % detail)
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------- decisions

def check(host: str, port: int = 443, timeout: float = 3.0,
          vantage: str = "localhost", source: Optional[str] = None) -> Result:
    """Probe both address families and decide what the answer means."""
    result = Result(target=host, port=port, vantage=vantage)

    v4, err4 = resolve(host, socket.AF_INET)
    v6, err6 = resolve(host, socket.AF_INET6)
    result.a_records, result.aaaa_records = v4, v6

    if not v4 and not v6:
        result.verdict = VERDICT_UNRESOLVED
        result.summary = "%s did not resolve from %s" % (host, vantage)
        result.error = err4 or err6 or ""
        result.hint = (
            "Either the name is wrong or this vantage has no DNS. Check which "
            "before reading anything into it: a broken resolver and a domain "
            "that does not exist look identical from here."
        )
        return result

    # Probe the first address of each family. Rotating through every address
    # would turn one check into N connects against a host we do not own.
    for family, addrs in ((socket.AF_INET, v4), (socket.AF_INET6, v6)):
        if not addrs:
            continue
        result.attempts.append(
            connect_once(addrs[0], family, port, timeout, source))

    v4a = next((a for a in result.attempts if a.family == "IPv4"), None)
    v6a = next((a for a in result.attempts if a.family == "IPv6"), None)

    # The case this tool exists for. AAAA published, IPv6 probe silent, IPv4
    # fine: the check is a coin flip, and the error it produces names the target
    # when it should name the probe.
    if v6a and v6a.outcome == TIMEOUT and (v4a is None or v4a.outcome == OK):
        result.verdict = VERDICT_BLACKHOLE
        result.summary = "IPv6 blackholed while IPv4 works for %s" % host
        result.hint = (
            "A check that lands on the AAAA record will hang for the full "
            "timeout and report a dead target. Either give this vantage "
            "working IPv6, pin the check to IPv4, or disable IPv6 for the "
            "probe. Do not raise the timeout: it makes the false report slower, "
            "not truer."
        )
        return result

    if v6a and v6a.outcome == TIMEOUT and v4a and v4a.outcome == TIMEOUT:
        result.verdict = VERDICT_TIMEOUT
        result.summary = "both families timed out for %s" % host
        result.hint = (
            "Two silent families from one vantage. The target may be down, or "
            "this vantage's egress may be. One measurement cannot separate "
            "them -- run compare() from a second vantage before paging anyone."
        )
        return result

    if not v4a and v6a and v6a.outcome in (OK, REFUSED):
        result.verdict = VERDICT_OK if v6a.outcome == OK else VERDICT_REFUSED
        result.summary = "IPv6-only target, no A record for %s" % host
        result.hint = (
            "Nothing to fall back to: if the IPv6 path breaks, monitoring has "
            "no second route and will report an outage it cannot distinguish "
            "from a probe failure."
        )
        return result

    # Anything that completed a handshake is the headline: a working path is the
    # answer, and the hint is where a degraded family gets recorded. Ordering
    # matters -- putting "both refused" above this would swallow the common
    # "IPv4 fine, IPv6 unreachable" pair and describe it as a port problem.
    if (v4a and v4a.outcome == OK) or (v6a and v6a.outcome == OK):
        used = [a.family for a in result.attempts if a.outcome == OK]
        result.verdict = VERDICT_OK
        result.summary = "reachable over %s for %s" % (" and ".join(used), host)
        if v6a and v6a.outcome != OK:
            result.hint = (
                "IPv4 works, so the check has a fallback, but the IPv6 path "
                "does not (%s). A resolver that prefers AAAA will be slower "
                "than it needs to be, and a check pinned to IPv6 will fail."
                % v6a.outcome
            )
        return result

    if v4a and v4a.outcome == REFUSED and v6a and v6a.outcome == REFUSED:
        result.verdict = VERDICT_REFUSED
        result.summary = "both families answered (refused) for %s" % host
        result.hint = (
            "Connection refused is an answer: the host is up and nothing is "
            "listening on this port. That is a target-side state, not a path "
            "problem, and it should not be reported as an outage of the path."
        )
        return result

    if v4a and v4a.outcome == REFUSED and not v6a:
        result.verdict = VERDICT_REFUSED
        result.summary = "IPv4 answered (refused) for %s" % host
        result.hint = (
            "The target answered and declined. No AAAA record exists, so there "
            "is no second route: if this path breaks, the check has nothing to "
            "fall back to."
        )
        return result

    if result.attempts and all(a.outcome == ERROR for a in result.attempts):
        result.verdict = VERDICT_PROBE_ERROR
        result.summary = "the probe could not run for %s" % host
        result.hint = (
            "Every attempt failed locally, before any packet reached the "
            "target. This is a problem with the invocation or this host's "
            "configuration -- not evidence about the target."
        )
        return result

    result.verdict = VERDICT_TIMEOUT
    result.summary = "could not reach %s over any family" % host
    return result


# ---------------------------------------------------------------- comparison

def compare(results: List[Result]) -> Dict:
    """Turn several vantages into one statement about where the fault is.

    This is the only honest way to answer "is it the target or the path?". One
    vantage produces a claim about its own path. Two vantages disagreeing is
    information; two vantages agreeing is weak evidence, because they may share
    an upstream.

    The rule: silence from one vantage while another reaches the target is a
    path problem, and it names the broken vantage. Silence from every vantage is
    a target problem, with the caveat that a shared upstream would produce the
    same picture -- which is why the caveat is printed rather than hidden.
    """
    if not results:
        return {"verdict": "no-measurement", "detail": "nothing to compare"}

    # A vantage that failed to run produced no measurement. Counting it as
    # "silent" would blame the target for our broken ssh; skipping it silently
    # would let the remaining vantage report "everything fine" while half the
    # comparison never happened. Neither is allowed to happen.
    broken = [r.vantage for r in results if r.error == "vantage-error"]
    if broken:
        return {
            "vantages": [r.vantage for r in results],
            "broken": broken,
            "verdict": "incomplete",
            "detail": (
                "No measurement from %s, so there is nothing to compare "
                "against. This says nothing about the target -- fix the "
                "vantage and run again. Reporting agreement from the remaining "
                "vantage would be a conclusion about an experiment that was "
                "never finished." % ", ".join(broken)
            ),
        }

    ok = [r for r in results if r.verdict == VERDICT_OK]
    silent = [r for r in results if r.verdict in (VERDICT_TIMEOUT, VERDICT_BLACKHOLE)]
    refused = [r for r in results if r.verdict == VERDICT_REFUSED]

    out = {
        "vantages": [r.vantage for r in results],
        "reached": [r.vantage for r in ok],
        "silent": [r.vantage for r in silent],
        "refused": [r.vantage for r in refused],
    }

    if ok and silent:
        out["verdict"] = "path"
        out["detail"] = (
            "Reached from %s but not from %s. The target answered somebody, so "
            "the fault is on the path from the silent vantage -- not the "
            "service. Act on %s's egress, not on the target."
            % (", ".join(out["reached"]), ", ".join(out["silent"]),
               ", ".join(out["silent"]))
        )
    elif silent and not ok:
        out["verdict"] = "target-or-shared-path"
        out["detail"] = (
            "Silent from every vantage (%s). That points at the target, with "
            "one caveat worth stating: if all vantages share an upstream, a "
            "fault there produces the same picture. Add a vantage outside that "
            "upstream before concluding."
            % ", ".join(out["silent"])
        )
    elif refused and not ok:
        out["verdict"] = "target"
        out["detail"] = (
            "Answered with refusal from %s. The target is up and not listening "
            "on this port. This is a target-side state; there is nothing to "
            "fix on the probe."
            % ", ".join(out["refused"])
        )
    elif ok:
        out["verdict"] = "ok"
        out["detail"] = "Reached from every vantage (%s)." % ", ".join(out["reached"])
    else:
        out["verdict"] = "mixed"
        out["detail"] = "Vantages disagree in a way this rule does not cover."

    return out
