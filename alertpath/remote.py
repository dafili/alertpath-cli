"""Run the same measurement from a second network vantage, over ssh.

Why this exists: a single probe can only report on its own path. When a check
says "timeout", one vantage cannot distinguish a dead target from a broken
egress, and that ambiguity is the entire reason this tool exists. Two vantages
resolve it -- silence from one while the other reaches the target is a path
problem, and it names which path.

Why ssh and not an API: a hosted probe service would mean an account, a key, a
dependency and a data trail leaving the machine, for a measurement that is one
TCP connect. Anything with ssh and python3 can be a vantage, which is usually
the box you already have.

The remote side needs nothing installed. This module ships the core source over
stdin and runs it there, so the numbers come from the same code as the local
measurement -- a comparison between two different implementations would be
comparing the tools, not the network.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Optional

CORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "core.py")

# The remote payload is assembled in this order: core source, then the
# parameters, then the call. The source has to come first because core.py opens
# with `from __future__ import annotations`, which Python rejects anywhere but
# the very top of a module. Getting this order wrong is not obvious from the
# local side -- it surfaces as "the vantage is broken" when our own payload is.
REMOTE_CALL = """
import json as _json, sys as _sys
_sys.stdout.write(_json.dumps(
    check(HOST, PORT, TIMEOUT, VANTAGE).to_dict()))
"""


def _core_source() -> str:
    return open(CORE, encoding="utf-8").read()


def probe_via(host: str, ssh_target: str, port: int = 443,
              timeout: float = 3.0, connect_timeout: int = 25,
              ssh_config: Optional[str] = None) -> dict:
    """Measure from ssh_target. Returns the remote Result as a dict.

    A failure to connect is reported as a vantage error rather than a timeout.
    That distinction matters: "I could not run the probe" is not evidence about
    the target, and reporting it as silence would manufacture exactly the false
    conclusion this tool is built to prevent.
    """
    vantage = "ssh:%s" % ssh_target
    # The parameters go in as a small preamble so the core source can stay
    # unchanged and identical to the local copy.
    preamble = "\nHOST=%r\nPORT=%d\nTIMEOUT=%r\nVANTAGE=%r\n" % (
        host, port, float(timeout), vantage)
    payload = _core_source() + preamble + REMOTE_CALL

    # A config with host aliases has to be passed explicitly when it is not in
    # ~/.ssh/config. On this fleet the aliases live in an absolute path outside
    # the home directory, and ssh will not find them on its own.
    cmd = ["ssh"]
    if ssh_config:
        cmd += ["-F", ssh_config]
    cmd += [
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=%d" % connect_timeout,
        ssh_target, "python3 -",
    ]
    try:
        proc = subprocess.run(cmd, input=payload, capture_output=True,
                              text=True, timeout=connect_timeout + 30)
    except FileNotFoundError:
        return {"vantage": vantage, "verdict": "vantage-error",
                "summary": "ssh not found on this machine",
                "detail": "install an ssh client, or drop --via"}
    except subprocess.TimeoutExpired:
        return {"vantage": vantage, "verdict": "vantage-error",
                "summary": "ssh to %s timed out" % ssh_target,
                "detail": "the vantage itself is unreachable; this is not "
                          "evidence about the target"}

    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        return {"vantage": vantage, "verdict": "vantage-error",
                "summary": "ssh to %s failed (exit %d)" % (ssh_target, proc.returncode),
                "detail": detail[-1] if detail else "no stderr"}

    text = (proc.stdout or "").strip()
    # Keep only the last line that parses: a login banner or a shell rc greeting
    # must not break the measurement.
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            return json.loads(line)
        except ValueError:
            continue
    return {"vantage": vantage, "verdict": "vantage-error",
            "summary": "remote probe returned no JSON",
            "detail": text[-300:]}
