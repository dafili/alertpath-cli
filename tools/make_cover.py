#!/usr/bin/env python3
"""Render the cover for the IPv6 blackhole post.

The figure has one job: make the 281 ms / 10,007 ms contrast legible in under a
second, on a phone, with no legend. So it is two bars on the same baseline, the
good one almost too small to see, and the label that the naive checker produced
sitting where the reader expects a verdict.

Every number on the image came from a real run on 2026-11-03. Nothing here is
an illustration of an idea -- the bars are the measurements.
"""
from PIL import Image, ImageDraw, ImageFont

W, H = 1600, 900
BG = (13, 17, 23)          # near-black, easier on OLED and matches the post
FG = (230, 237, 243)
DIM = (110, 122, 138)
GOOD = (63, 185, 80)       # the IPv4 answer, which was correct
BAD = (248, 81, 73)        # the report, which was wrong
ACCENT = (88, 166, 255)

MONO = "/usr/share/fonts/truetype/hack/Hack-Regular.ttf"
MONO_B = "/usr/share/fonts/truetype/hack/Hack-Bold.ttf"
SANS_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"


def f(path, size):
    return ImageFont.truetype(path, size)


img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)

M = 90
d.text((M, 62), "same hostname · same port · same instant", font=f(MONO, 24), fill=DIM)

# Position the caption from the measured width of the number. Hardcoding an
# offset is how the first draft ended up with "281 ms" printed through its own
# label -- the same class of mistake as asserting on a fixed address.
big = f(MONO_B, 96)
lab = f(SANS, 30)
for num, cap, col, ytop in (
        ("281 ms", "the target answered over IPv4", GOOD, 108),
        ("10,007 ms", "the check reported the target DOWN", BAD, 250)):
    d.text((M, ytop), num, font=big, fill=col)
    x = M + d.textlength(num, font=big) + 44
    d.text((x, ytop + 44), cap, font=lab, fill=FG)

# Two bars on one axis. The good one is deliberately almost invisible: that
# disproportion IS the finding, and scaling it up for legibility would lie.
bar_x, bar_w = M, W - M * 2 - 40
d.text((M, 400), "time to answer", font=f(MONO, 22), fill=DIM)

y1 = 440
d.rectangle([bar_x, y1, bar_x + 46, y1 + 34], fill=GOOD)
d.text((bar_x + 62, y1 + 1), "IPv4   ok           281 ms", font=f(MONO, 26), fill=GOOD)

y2 = 500
d.rectangle([bar_x, y2, bar_x + bar_w, y2 + 34], fill=BAD)
d.text((bar_x + bar_w - 300, y2 + 1), "10,007 ms", font=f(MONO_B, 26), fill=(20, 24, 30))
d.text((bar_x + 12, y2 + 1), "IPv6   timeout", font=f(MONO, 26), fill=(20, 24, 30))

d.line([(M, 585), (W - M, 585)], fill=(48, 54, 61), width=2)

d.text((M, 615), '$ alertpath --check-host demo.internal', font=f(MONO, 26), fill=ACCENT)
d.text((M, 658), 'demo.internal:443  ->  IPV6-BLACKHOLE', font=f(MONO_B, 30), fill=FG)
d.text((M, 702), 'IPv4 104.20.23.154      ok         281ms', font=f(MONO, 24), fill=GOOD)
d.text((M, 736), 'IPv6 2001:db8::1        timeout   10007ms', font=f(MONO, 24), fill=BAD)

d.text((M, 790), "exit 3 = the probe is blind, not the service", font=f(MONO_B, 26), fill=ACCENT)

d.text((W - M - 470, 845), "github.com/dafili/alertpath-cli", font=f(MONO, 22), fill=DIM)

img.save("/vol2/1000/临时上传/alertpath-cover-16x9.png", optimize=True)
img.save("/vol2/1000/临时上传/alertpath-cover-16x9.jpg", quality=92, optimize=True)

# Dev.to also wants a 1:1 for social cards.
side = 1000
sq = Image.new("RGB", (side, side), BG)
s = ImageDraw.Draw(sq)
s.text((60, 70), "same host, same instant", font=f(MONO, 22), fill=DIM)
s.text((60, 116), "281 ms", font=f(MONO_B, 84), fill=GOOD)
s.text((60, 208), "vs", font=f(MONO, 28), fill=DIM)
s.text((60, 246), "10,007 ms", font=f(MONO_B, 84), fill=BAD)
s.line([(60, 372), (side - 60, 372)], fill=(48, 54, 61), width=2)
s.text((60, 402), "IPv4 answered in 281 ms.", font=f(SANS, 30), fill=FG)
s.text((60, 444), "The monitor reported it DOWN.", font=f(SANS, 30), fill=FG)
s.line([(60, 520), (side - 60, 520)], fill=(48, 54, 61), width=2)
s.text((60, 550), "IPV6-BLACKHOLE", font=f(MONO_B, 34), fill=ACCENT)
s.text((60, 592), "exit 3 = the probe is blind,", font=f(MONO, 22), fill=FG)
s.text((60, 622), "not the service", font=f(MONO, 22), fill=FG)
s.text((60, 900), "github.com/dafili/alertpath-cli", font=f(MONO, 18), fill=DIM)
sq.save("/vol2/1000/临时上传/alertpath-cover-1x1.png", optimize=True)
sq.save("/vol2/1000/临时上传/alertpath-cover-1x1.jpg", quality=92, optimize=True)

print("done")
