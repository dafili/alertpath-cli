# alertpath

**Your check said "timeout". That word cannot tell you whether the target is dead or your probe is.**

`alertpath` is a single-purpose CLI that answers one question properly: *is this
path broken, or is the thing measuring it broken?* It keeps three outcomes apart
that most checkers merge into one string, and it exits with a different code for
each of them.

Standard library only. No cloud, no API key, no agent, no dependency. Read-only:
DNS lookups and TCP connects. No payload is sent and the socket is closed as soon
as the handshake completes.

```console
$ alertpath --check-host example.com
example.com:443  ->  OK
  vantage : localhost
  summary : reachable over IPv4 and IPv6 for example.com
  A       : 104.20.23.154, 172.66.147.243
  AAAA    : 2606:4700:10::ac42:93f3, 2606:4700:10::6814:179a
```

```console
$ echo $?
0
```

---

## The bug this exists for

A monitor reports `timeout of 48048ms exceeded` against a site that is
perfectly healthy. Somebody gets paged. The site is fine. The monitor is fine.
What is broken is the *path between them*, and nothing in the alert says so,
because the alert was written by a program that collapsed four different
situations into the word "timeout".

The shape of it:

1. The host has an AAAA record published and an IPv6 route in its table.
2. Packets to that route are dropped rather than rejected.
3. The connect call therefore does not fail. It **waits**.
4. When the deadline expires the checker reports... the target's name.

That last step is the defect. A dropped packet produces the same string as a
dead server, and the two have opposite owners.

### The measurement that separates them

I ran both address families against the same hostname from the same machine, on
the same day:

| Family | Result | Time |
|---|---|---|
| IPv4 | `ok` | **259 ms** |
| IPv6 | `timeout` | **48,048 ms** |

Same name, same port, same moment. A 185× difference in what the user waited
for, and the slow one was not the remote side's fault. Anything that resolves
AAAA first — which is most modern stacks, and the OS preference in a
happy-eyeballs resolver — is a coin flip on this host, and when the coin lands
wrong the report names the wrong party.

`alertpath` reports that as `ipv6-blackhole` and exits `3`, which is a distinct
code precisely so a monitor can stop blaming the target:

```console
$ alertpath --check-host example.com
example.com:443  ->  IPV6-BLACKHOLE
  vantage : localhost
  summary : IPv6 blackholed while IPv4 works for example.com
  IPv4 104.20.23.154        ok         259ms
  IPv6 2606:4700:10::ac42:93f3  timeout  3000ms  no response before 3s deadline
  hint    : A check that lands on the AAAA record will hang for the full
            timeout and report a dead target. Either give this vantage working
            IPv6, pin the check to IPv4, or disable IPv6 for the probe. Do not
            raise the timeout: it makes the false report slower, not truer.
```

> The 259 ms is reproducible today with `alertpath --check-host example.com`.
> The 48,048 ms came from a host whose IPv6 route existed and dropped packets;
> it is not reproducible from an arbitrary machine, which is exactly why the
> tool reports the *classification* rather than claiming a number.

---

## Exit codes are the interface

A monitor reads a code, not a sentence.

| Code | Verdict | What it means | Whose problem |
|---|---|---|---|
| `0` | `ok` | a handshake completed | nobody |
| `1` | `refused` | the kernel got an answer and the answer was no | **target** |
| `2` | `timeout` | nothing answered before the deadline | **path or target** — unresolved |
| `3` | `ipv6-blackhole` | AAAA silently dead, IPv4 works | **the probe's egress** |
| `4` | `unresolved` | the name did not resolve from here | target's DNS or this host's resolver |
| `5` | `probe-error` | the check could not run at all | **this invocation** |

`refused` and `timeout` are the pair that matters most. **A refused connection is
an answer.** It means the host is up and nothing is listening on that port, which
is a target-side state that no amount of probe repair will change. A timeout is
the absence of an answer, and it is the only outcome where the probe is a
suspect. Merging them is what produces a page at 3am that cannot be acted on.

`probe-error` is the code that keeps the tool honest about itself. A typo in
`--bind`, a missing route family, a socket the kernel refused to create — those
are facts about *our invocation*, not about the target. They get their own code
so they can never be quietly averaged into a verdict about somebody else's server.

---

## Three false greens it catches

### 1. The silent family
`ok` over IPv4, silence over IPv6. Every uptime graph is green, and one in
however-many checks lands on the AAAA record and hangs. The dashboard says the
site is slow; the site is fine. See above.

### 2. The refusal reported as an outage
`Connection refused` means the target answered. Reporting it as an outage is
wrong in a way that wastes the most expensive thing you have: somebody's night.
`alertpath` exits `1`, not `2`, because those are different phone calls.

**A real example of the inverse trap:** `example.com` on port 9 is not refused,
it is *dropped* by policy. So `alertpath --check-host example.com --port 9` exits
`2`, not `1`. The target is alive and declining to answer. If your checker calls
that "down", it is describing a firewall as a dead server.

### 3. The vantage that was never asked
This one is in the tool because I shipped it wrong first. `--compare` with a
second vantage that fails to connect must **not** fall back to "the local vantage
says OK, so everything is fine". A missing measurement is not agreement. It is an
unfinished experiment, and the tool says so:

```console
$ alertpath --check-host example.com --via eu --compare
...
compare -> INCOMPLETE
  No measurement from ssh:eu, so there is nothing to compare against. This says
  nothing about the target -- fix the vantage and run again. Reporting agreement
  from the remaining vantage would be a conclusion about an experiment that was
  never finished.
```

---

## Comparing two vantages

One probe produces a claim about its own path. Two probes disagreeing is
information. This is the only honest way to answer *"is it the target or the
path?"*, and it is the reason `--compare` exists.

```console
$ alertpath --check-host example.com --via aliyun --compare \
    --ssh-config ~/.ssh/config
example.com:443  ->  OK       vantage : localhost
example.com:443  ->  OK       vantage : ssh:aliyun
compare -> OK
  reached : localhost, ssh:aliyun
```

The decision rule, stated plainly:

| Picture | Verdict | Reasoning |
|---|---|---|
| one vantage reaches, another is silent | **`path`** | the target answered somebody, so the fault is on the failing path — and it names which one |
| every vantage silent | **`target-or-shared-path`** | points at the target, *with* the caveat that a shared upstream produces the identical picture |
| answered with refusal | **`target`** | up and not listening; nothing to fix on the probe |
| a vantage never ran | **`incomplete`** | no conclusion is available, and none is offered |

That middle row is why the caveat is printed instead of hidden. Two vantages
inside the same AS agreeing with each other is weaker evidence than it looks, and
a tool that reports it as certainty is doing the same thing as the timeout string
this tool was built to replace.

### The remote side needs nothing installed

`--via` ships the core source over `ssh` and runs it with `python3 -` on the far
side. Anything with ssh and a Python 3 interpreter is a vantage — usually the box
you already have in the other region. The numbers come from the same code as the
local measurement, because comparing two different implementations would be
comparing the tools rather than the network.

If your ssh host aliases are not in `~/.ssh/config`, pass `--ssh-config PATH`.
This matters more than it sounds: without it, `ssh` reports `Could not resolve
hostname`, which `--compare` correctly refuses to read as silence — you get
`incomplete`, not a story about your server.

---

## Install

Not on PyPI yet. From source:

```bash
git clone https://github.com/dafili/alertpath-cli
cd alertpath-cli
python3 -m alertpath --check-host example.com
```

Or drop the two files in and run them:

```bash
python3 -c "import alertpath.cli, sys; sys.exit(alertpath.cli.main())" --check-host example.com
```

Requires Python 3.8+. No third-party packages, ever. The whole point of a checker
is that it works on the machine where things are broken, and that machine
frequently has no network, no package manager, and no patience.

---

## Usage

```
alertpath --check-host HOST [--port 443] [--timeout 3.0]
          [--bind ADDR] [--via TARGET ...] [--compare]
          [--json] [--verbose]
```

| Flag | Purpose |
|---|---|
| `--check-host` | hostname or address to test (required) |
| `--port` | TCP port, default `443` |
| `--timeout` | per-connect deadline in seconds, default `3.0` |
| `--bind` | source address; for multi-homed or VPN hosts, a second egress on the same box |
| `--via` | also measure from this ssh target (repeatable) |
| `--compare` | with `--via`, report whether silence is the target or the path |
| `--json` | machine-readable output |
| `-v` | print every attempt, not just failures |

---

## Using it in a monitor

The point of distinct exit codes is that they can page different people.

```bash
alertpath --check-host api.example.com --timeout 3
case $? in
  0) ;;                                    # fine
  1) echo "port closed on the target";;     # target team
  3) echo "this probe has no working IPv6"; exit 0;;   # do NOT page
  2) echo "silent -- run compare before paging";;
  5) echo "the check itself did not run"; exit 0;;
esac
```

Two lines there are the whole argument. Exit `3` should not wake anybody up,
because it is a fact about the probe. Exit `5` should not either, because a check
that never ran produced no evidence.

---

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The network is stubbed in every test but one. The exceptions are deliberate: one
test uses loopback, which is always available and needs no internet. Three tests
exist because this code was wrong first:

- the verdict ordering that swallowed IPv6-only targets and never printed their
  warning;
- the `OSError` branch that counted `EINVAL` from a bad `--bind` as a refusal
  from the target;
- the comparison that let a vantage that never ran be outvoted by one that did.

---

## What it does not do

- **No HTTP.** It stops at the TCP handshake. A `200` that says "something went
  wrong" is a different check, and mixing them is how a health endpoint ends up
  proving that a process is running while users get errors.
- **No history.** It reports one measurement. Trend and rate belong to whatever
  stores the exit codes.
- **No TLS inspection.** Whether a certificate is served correctly is a separate
  question with a separate set of false greens.
- **No cloud probe network.** `--via` uses hosts you already control. A hosted
  vantage is an account, a key, and a data trail for a measurement that is one
  TCP connect.

---

## Why I wrote it

I build audit tooling for Linux servers, and the same failure kept showing up in
different costumes: a check that reports success while the thing it was supposed
to verify is broken. The instrument works, the answer is about a different
question, and the report names the wrong party.

This is the smallest piece of that: one TCP connect, described honestly enough
that you can tell whose problem you are looking at.

The paid tool I maintain, which audits disk, inodes, backup freshness, systemd
units, memory, load, time sync and cron on a single server without an agent, is
at **https://vaultcheck.dafili.cn** — the same idea applied to nine more checks.
This one is free, MIT, and enough on its own.

If you find a case where these three outcomes still merge, that is a bug and I
want it: open an issue with the exit code you got and the one you expected.

## License

MIT. See [LICENSE](LICENSE).
