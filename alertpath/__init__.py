"""alertpath -- does this probe's answer mean what you think it means?

A checker that reports a timeout cannot tell you whether the target failed or the
probe did. Those are different problems with opposite owners, and one string
described both of them for years.

This package keeps three outcomes apart instead of collapsing them:

    ok        the kernel completed a TCP handshake
    refused   the kernel got an answer and the answer was no
    timeout   nothing answered before the deadline

`refused` is an answer. `timeout` is the absence of one, and it is the only
outcome where the probe itself is a suspect. On a dual-stack host that resolves
AAAA records without a working IPv6 path, a check that lands on the AAAA address
hangs until some outer clock expires and then reports a dead target -- which is
how a healthy site becomes a 48-second timeout.

Standard library only. No cloud, no API keys, no agent. Read-only: DNS lookups
and outbound TCP connects, no payload sent.
"""

__version__ = "0.1.0"
