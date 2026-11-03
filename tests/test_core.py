"""The decision table, with the network stubbed out.

The point of these tests is not to reach the internet. It is to pin the three
outcomes the connect helper must keep distinct, and the verdict each combination
of them produces. One test does use loopback, which is always available.

Every test here exists because the merged version of these outcomes produced a
wrong answer at some point: a healthy site reported dead, a refused port
reported as an outage, or a working IPv4 path hidden behind a silent IPv6 one.
"""

import socket
import unittest
from unittest import mock

from alertpath import core


def _attempts(*specs):
    """(family, outcome) pairs -> Attempt list, in the order given."""
    out = []
    for family, outcome in specs:
        label = "IPv6" if family == socket.AF_INET6 else "IPv4"
        addr = "2001:db8::1" if family == socket.AF_INET6 else "192.0.2.1"
        out.append(core.Attempt(label, addr, outcome, 0.01, ""))
    return out


class TestConnectOnce(unittest.TestCase):
    """connect_once has to keep 'answered' apart from 'said nothing'."""

    def test_handshake_is_ok(self):
        with mock.patch.object(socket, "socket") as sock_cls:
            sock_cls.return_value.connect.return_value = None
            a = core.connect_once("127.0.0.1", socket.AF_INET, 80, 1.0)
        self.assertEqual(core.OK, a.outcome)
        self.assertEqual("IPv4", a.family)

    def test_deadline_is_timeout_not_refused(self):
        # The distinction the whole tool rests on: silence means the probe's own
        # path is a candidate cause, so it must not be reported as an answer.
        with mock.patch.object(socket, "socket") as sock_cls:
            sock_cls.return_value.connect.side_effect = socket.timeout()
            a = core.connect_once("192.0.2.1", socket.AF_INET, 443, 1.0)
        self.assertEqual(core.TIMEOUT, a.outcome)
        self.assertIn("deadline", a.detail)

    def test_refusal_is_an_answer(self):
        with mock.patch.object(socket, "socket") as sock_cls:
            sock_cls.return_value.connect.side_effect = ConnectionRefusedError(
                111, "Connection refused")
            a = core.connect_once("192.0.2.1", socket.AF_INET, 443, 1.0)
        self.assertEqual(core.REFUSED, a.outcome)

    def test_no_route_is_not_a_timeout(self):
        # ENETUNREACH comes back immediately: the kernel answered. Reporting it
        # as a timeout would blame the probe for a fact about this host's table.
        with mock.patch.object(socket, "socket") as sock_cls:
            err = OSError(101, "Network is unreachable")
            err.errno = 101
            sock_cls.return_value.connect.side_effect = err
            a = core.connect_once("2001:db8::1", socket.AF_INET6, 443, 1.0)
        self.assertEqual(core.REFUSED, a.outcome)
        self.assertIn("no route", a.detail)

    def test_socket_is_closed_even_on_success(self):
        with mock.patch.object(socket, "socket") as sock_cls:
            core.connect_once("127.0.0.1", socket.AF_INET, 80, 1.0)
        sock_cls.return_value.close.assert_called_once()

    def test_loopback_really_connects(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            a = core.connect_once("127.0.0.1", socket.AF_INET, port, 2.0)
            self.assertEqual(core.OK, a.outcome)
        finally:
            server.close()


class TestVerdicts(unittest.TestCase):
    """The combinations, and what each one means about whose problem it is."""

    def _run(self, v4_addr, v6_addr, attempts):
        with mock.patch.object(core, "resolve") as res, \
             mock.patch.object(core, "connect_once") as conn:
            # An empty string means "no record in this family", which is what
            # core.resolve reports as an empty list. Building [""] here would
            # send the code a probe against an address that does not exist.
            res.side_effect = lambda host, fam: (
                ([v4_addr], "") if fam == socket.AF_INET else ([v6_addr], "")) \
                if (v4_addr if fam == socket.AF_INET else v6_addr) else ([], "")
            conn.side_effect = list(attempts)
            return core.check("example.test", 443, 1.0)

    def test_ipv4_ok_is_ok(self):
        r = self._run("192.0.2.1", "", _attempts((socket.AF_INET, core.OK)))
        self.assertEqual(core.VERDICT_OK, r.verdict)
        self.assertEqual(core.EXIT_OK, r.exit_code)

    def test_ipv6_blackhole_is_the_reason_this_tool_exists(self):
        # IPv4 fine, IPv6 silent. The old behaviour: a timeout string that names
        # the target. The truth: the probe has no working IPv6 path.
        r = self._run("192.0.2.1", "2001:db8::1",
                      _attempts((socket.AF_INET, core.OK),
                                (socket.AF_INET6, core.TIMEOUT)))
        self.assertEqual(core.VERDICT_BLACKHOLE, r.verdict)
        self.assertEqual(core.EXIT_BLACKHOLE, r.exit_code)
        self.assertIn("AAAA", r.hint)

    def test_both_silent_is_timeout(self):
        r = self._run("192.0.2.1", "2001:db8::1",
                      _attempts((socket.AF_INET, core.TIMEOUT),
                                (socket.AF_INET6, core.TIMEOUT)))
        self.assertEqual(core.VERDICT_TIMEOUT, r.verdict)
        self.assertEqual(core.EXIT_TIMEOUT, r.exit_code)

    def test_both_refused_is_refused_not_an_outage(self):
        # Ordering regression: this case used to be swallowed by the "reachable"
        # branch and described as a path failure.
        r = self._run("192.0.2.1", "2001:db8::1",
                      _attempts((socket.AF_INET, core.REFUSED),
                                (socket.AF_INET6, core.REFUSED)))
        self.assertEqual(core.VERDICT_REFUSED, r.verdict)
        self.assertEqual(core.EXIT_REFUSED, r.exit_code)

    def test_ipv4_ok_with_ipv6_enetunreach_stays_ok(self):
        # A working path is the headline. The degraded family belongs in the
        # hint, not in the verdict.
        r = self._run("192.0.2.1", "2001:db8::1",
                      _attempts((socket.AF_INET, core.OK),
                                (socket.AF_INET6, core.REFUSED)))
        self.assertEqual(core.VERDICT_OK, r.verdict)
        self.assertIn("IPv6", r.hint)

    def test_ipv6_only_target_is_flagged(self):
        r = self._run("", "2001:db8::1", _attempts((socket.AF_INET6, core.OK)))
        self.assertEqual(core.VERDICT_OK, r.verdict)
        self.assertIn("fall back", r.hint)

    def test_nothing_resolves(self):
        with mock.patch.object(core, "resolve", side_effect=lambda h, f: ([], "")):
            r = core.check("does-not-exist.invalid", 443, 1.0)
        self.assertEqual(core.VERDICT_UNRESOLVED, r.verdict)
        self.assertEqual(core.EXIT_UNRESOLVED, r.exit_code)

    def test_vantage_is_always_in_the_result(self):
        # A verdict without a vantage is a claim nobody can check.
        r = self._run("192.0.2.1", "", _attempts((socket.AF_INET, core.OK)))
        self.assertEqual("localhost", r.vantage)
        self.assertEqual("localhost", r.to_dict()["vantage"])


class TestCompare(unittest.TestCase):
    """Two vantages is the only way to say 'the path, not the target'."""

    def _r(self, vantage, verdict):
        return core.Result(target="example.test", port=443, vantage=vantage,
                           verdict=verdict)

    def test_one_silent_one_reaching_is_a_path_problem(self):
        cmp = core.compare([
            self._r("localhost", core.VERDICT_OK),
            self._r("ssh:eu", core.VERDICT_TIMEOUT),
        ])
        self.assertEqual("path", cmp["verdict"])
        self.assertIn("ssh:eu", cmp["detail"])
        self.assertIn("not the service", cmp["detail"])

    def test_all_silent_points_at_target_with_the_caveat_stated(self):
        cmp = core.compare([
            self._r("localhost", core.VERDICT_TIMEOUT),
            self._r("ssh:eu", core.VERDICT_TIMEOUT),
        ])
        self.assertEqual("target-or-shared-path", cmp["verdict"])
        # The caveat is not decoration: a shared upstream produces this picture
        # and concluding "target down" from it is how people page the wrong team.
        self.assertIn("upstream", cmp["detail"])

    def test_refusal_only_is_target_side(self):
        cmp = core.compare([self._r("localhost", core.VERDICT_REFUSED)])
        self.assertEqual("target", cmp["verdict"])

    def test_all_ok(self):
        cmp = core.compare([self._r("localhost", core.VERDICT_OK),
                            self._r("ssh:eu", core.VERDICT_OK)])
        self.assertEqual("ok", cmp["verdict"])

    def test_empty_input_does_not_pretend(self):
        self.assertEqual("no-measurement", core.compare([])["verdict"])


if __name__ == "__main__":
    unittest.main()
