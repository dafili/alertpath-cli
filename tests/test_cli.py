"""CLI contract: exit codes, JSON shape, and the vantage-error rule.

These tests exist because the exit code is the interface a monitor reads. If an
exit code stops distinguishing cases, every dashboard downstream silently
flattens back into "something is wrong", which is the failure this tool was
built to end.
"""

import io
import json
import socket
import unittest
from contextlib import redirect_stdout
from unittest import mock

from alertpath import cli, core


def _run(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli.main(argv)
    return code, buf.getvalue()


def _fake_check(verdict):
    def inner(*a, **kw):
        return core.Result(target="example.test", port=443, vantage="localhost",
                           verdict=verdict, summary="stub")
    return inner


class TestExitCodes(unittest.TestCase):

    def test_ok_is_zero(self):
        with mock.patch.object(core, "check", _fake_check(core.VERDICT_OK)):
            code, _ = _run(["--check-host", "example.test"])
        self.assertEqual(0, code)

    def test_refused_is_one(self):
        with mock.patch.object(core, "check", _fake_check(core.VERDICT_REFUSED)):
            code, _ = _run(["--check-host", "example.test"])
        self.assertEqual(1, code)

    def test_timeout_is_two(self):
        with mock.patch.object(core, "check", _fake_check(core.VERDICT_TIMEOUT)):
            code, _ = _run(["--check-host", "example.test"])
        self.assertEqual(2, code)

    def test_blackhole_is_three_and_not_folded_into_timeout(self):
        # The one case where a monitor should stop blaming the target.
        with mock.patch.object(core, "check", _fake_check(core.VERDICT_BLACKHOLE)):
            code, _ = _run(["--check-host", "example.test"])
        self.assertEqual(3, code)

    def test_unresolved_is_four(self):
        with mock.patch.object(core, "check", _fake_check(core.VERDICT_UNRESOLVED)):
            code, _ = _run(["--check-host", "example.test"])
        self.assertEqual(4, code)

    def test_missing_host_argument_is_a_usage_error(self):
        with self.assertRaises(SystemExit) as ctx:
            _run([])
        self.assertEqual(2, ctx.exception.code)


class TestJsonShape(unittest.TestCase):

    def test_json_carries_vantage_and_dns(self):
        res = core.Result(target="example.test", port=443, vantage="localhost",
                          verdict=core.VERDICT_OK, summary="fine")
        res.a_records = ["192.0.2.1"]
        res.attempts = [core.Attempt("IPv4", "192.0.2.1", core.OK, 0.012, "")]
        with mock.patch.object(core, "check", lambda *a, **k: res):
            _, out = _run(["--check-host", "example.test", "--json"])
        payload = json.loads(out)
        r = payload["results"][0]
        self.assertEqual("localhost", r["vantage"])
        self.assertEqual(["192.0.2.1"], r["dns"]["A"])
        self.assertEqual(12.0, r["attempts"][0]["elapsed_ms"])
        self.assertEqual(0, r["exit_code"])

    def test_json_has_no_compare_key_without_via(self):
        with mock.patch.object(core, "check", _fake_check(core.VERDICT_OK)):
            _, out = _run(["--check-host", "example.test", "--json"])
        self.assertNotIn("compare", json.loads(out))


class TestComparePath(unittest.TestCase):

    def test_second_vantage_silent_turns_verdict_into_a_path_problem(self):
        local = core.Result(target="example.test", port=443, vantage="localhost",
                            verdict=core.VERDICT_TIMEOUT, summary="stub")
        remote = {"target": "example.test", "port": 443, "vantage": "ssh:eu",
                  "verdict": core.VERDICT_OK, "summary": "reachable",
                  "hint": "", "dns": {"A": ["192.0.2.1"], "AAAA": []},
                  "attempts": [], "exit_code": 0}
        with mock.patch.object(core, "check", lambda *a, **k: local), \
             mock.patch.object(cli, "probe_via", lambda *a, **k: remote):
            code, out = _run(["--check-host", "example.test",
                              "--via", "eu", "--compare"])
        self.assertIn("PATH", out.upper())
        self.assertEqual(2, code)   # the path is broken, not the target

    def test_vantage_error_is_not_outvoted_by_the_local_measurement(self):
        # "I could not ask" is not "they said nothing". Returning the local
        # verdict here would let a broken ssh connection masquerade as a
        # conclusion about the target.
        local = core.Result(target="example.test", port=443, vantage="localhost",
                            verdict=core.VERDICT_OK, summary="stub")
        failed = {"vantage": "ssh:eu", "verdict": "vantage-error",
                  "summary": "ssh to eu failed", "detail": "Permission denied"}
        with mock.patch.object(core, "check", lambda *a, **k: local), \
             mock.patch.object(cli, "probe_via", lambda *a, **k: failed):
            code, out = _run(["--check-host", "example.test", "--via", "eu"])
        self.assertEqual(cli.EXIT_VANTAGE_ERROR, code)
        self.assertIn("Permission denied", out)


class TestRemotePayload(unittest.TestCase):

    def test_remote_result_round_trips_through_json(self):
        res = core.Result(target="example.test", port=443, vantage="ssh:eu",
                          verdict=core.VERDICT_BLACKHOLE, summary="silent v6")
        res.a_records = ["192.0.2.1"]
        res.aaaa_records = ["2001:db8::1"]
        res.attempts = [core.Attempt("IPv6", "2001:db8::1", core.TIMEOUT, 3.0, "")]
        back = cli._from_remote("example.test", 443, res.to_dict())
        self.assertEqual(core.VERDICT_BLACKHOLE, back.verdict)
        self.assertEqual("ssh:eu", back.vantage)
        self.assertEqual(core.TIMEOUT, back.attempts[0].outcome)

    def test_remote_vantage_error_is_marked(self):
        back = cli._from_remote("example.test", 443,
                                {"vantage": "ssh:eu", "verdict": "vantage-error",
                                 "summary": "boom", "detail": "x"})
        self.assertEqual("vantage-error", back.error)


if __name__ == "__main__":
    unittest.main()
