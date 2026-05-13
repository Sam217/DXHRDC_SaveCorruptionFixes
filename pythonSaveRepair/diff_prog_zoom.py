"""One-shot diagnostic: zoom in on progression-header differences between
GAMER50 (corrupt) and GAMER51 (self-healed, 18 min later).

Run from anywhere:  python pythonSaveRepair/diff_prog_zoom.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from save_repair_tool import read_save  # noqa: E402

SAVES = os.path.normpath(os.path.join(HERE, "..", "238010", "remote"))

a = read_save(os.path.join(SAVES, "GAMER50_4"))
b = read_save(os.path.join(SAVES, "GAMER51_4"))

diffs = [i for i in range(len(a)) if a[i] != b[i]]
ranges = []
start = diffs[0]
prev = diffs[0]
for off in diffs[1:]:
    if off - prev <= 8:
        prev = off
    else:
        ranges.append((start, prev))
        start = off
        prev = off
ranges.append((start, prev))

prog_ranges = [r for r in ranges if r[1] < 0xF0000]
print(f"=== {len(prog_ranges)} ranges in progression header (offset < 0xF0000) ===\n")

for i, (s, e) in enumerate(prog_ranges):
    length = e - s + 1
    ctx_lo = max(0, s - 16)
    ctx_hi = min(len(a), e + 17)
    a_ctx = a[ctx_lo:ctx_hi]
    b_ctx = b[ctx_lo:ctx_hi]
    print(f"--- Range #{i}: offset {s:#x}-{e:#x} (len={length}) ---")

    def show(buf, off, label):
        ascii_repr = "".join(chr(c) if 32 <= c < 127 else "." for c in buf)
        print(f"  {label} @{off:#x}: {buf.hex(' ')}")
        print(f"  {label} ascii  : {ascii_repr}")

    show(a_ctx, ctx_lo, "GAMER50")
    show(b_ctx, ctx_lo, "GAMER51")
    print(f"  diff GAMER50[{s:#x}:{e+1:#x}] = {a[s:e+1].hex(' ')}")
    print(f"  diff GAMER51[{s:#x}:{e+1:#x}] = {b[s:e+1].hex(' ')}")
    print()
