"""Locate the painkiller count on disk by examining ACTUAL byte differences
between GAMER51 (count=4) and GAMER25 (count=12) outside the known
runaway-writer corruption regions.

Known corruption regions in GAMER25 (per scan-anomalies):
  region #0: 0x1ac000..0x1b4800  (also present in GAMER51 baseline)
  region #1: 0x1fb000..0x203800  (unique to GAMER25 = real corruption)
  earlier byte-diff also flagged 0x211355..0x217298 (24KB)

So the diff regions to TRUST as real game-state changes (movement, NPC
state, inventory) are everything OUTSIDE these corrupt blocks.

What we know about the painkiller change between the two saves:
  - Count: 4 -> 12 (uint16 LE in memory per CheatEngine)
  - The user also moved ~15m in the sewer area
  - No other significant changes
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from save_repair_tool import read_save  # noqa: E402

SAVES = os.path.normpath(os.path.join(HERE, "..", "238010", "remote"))
PROG_BOUNDARY = 0xF0000

# Corruption regions in GAMER25 from scan-anomalies + byte-diff history.
CORRUPT_REGIONS = [
    (0x1ac000, 0x1b4800),  # baseline (also in GAMER51) — exclude
    (0x1fb000, 0x203800),  # GAMER25-unique corruption
    (0x211355, 0x217298),  # earlier byte-diff finding
]

GAMER51 = read_save(os.path.join(SAVES, "GAMER51_4"))
GAMER25 = read_save(os.path.join(SAVES, "GAMER25_4"))

print(f"Buffer size: {len(GAMER51):#x}")
print()


def in_corrupt(off):
    for lo, hi in CORRUPT_REGIONS:
        if lo <= off < hi:
            return True
    return False


def collapse(diffs, gap=4):
    if not diffs:
        return []
    out = []
    s = diffs[0]
    p = diffs[0]
    for o in diffs[1:]:
        if o - p <= gap:
            p = o
        else:
            out.append((s, p))
            s = o
            p = o
    out.append((s, p))
    return out


# Find all differing offsets that are NOT in known corrupt regions.
diffs = [i for i in range(len(GAMER51)) if GAMER51[i] != GAMER25[i] and not in_corrupt(i)]
ranges = collapse(diffs, gap=4)

prog_ranges = [r for r in ranges if r[1] < PROG_BOUNDARY]
world_ranges = [r for r in ranges if r[0] >= PROG_BOUNDARY]

print(f"Total non-corrupt differing bytes : {len(diffs):,}")
print(f"Collapsed into ranges (gap<=4)    : {len(ranges)}")
print(f"  in progression header           : {len(prog_ranges)}")
print(f"  in world state                  : {len(world_ranges)}")
print()


def show(off_lo, off_hi, before=8, after=8):
    a = max(0, off_lo - before)
    b = min(len(GAMER51), off_hi + 1 + after)
    h51 = GAMER51[a:b].hex(" ")
    h25 = GAMER25[a:b].hex(" ")
    asc51 = "".join(chr(c) if 32 <= c < 127 else "." for c in GAMER51[a:b])
    asc25 = "".join(chr(c) if 32 <= c < 127 else "." for c in GAMER25[a:b])
    print(f"    G51 @{a:#x}: {h51}")
    print(f"    G51 ascii  : {asc51}")
    print(f"    G25 @{a:#x}: {h25}")
    print(f"    G25 ascii  : {asc25}")


# === Progression-header diffs — full context (this is where inventory SHOULD live) ===
print("=" * 75)
print("PROGRESSION-HEADER DIFFS (these are the candidate inventory/stat changes)")
print("=" * 75)
if not prog_ranges:
    print("  (none)")
else:
    for i, (s, e) in enumerate(prog_ranges):
        length = e - s + 1
        print(f"\n--- prog #{i}: {s:#x}-{e:#x} (len={length}) ---")
        print(f"    G51 bytes : {GAMER51[s:e+1].hex(' ')}")
        print(f"    G25 bytes : {GAMER25[s:e+1].hex(' ')}")
        show(s, e, before=16, after=16)

        # interpret the differing bytes as numbers and report deltas
        if length <= 4:
            v51_u8 = GAMER51[s]
            v25_u8 = GAMER25[s]
            print(f"    u8 first byte: G51={v51_u8} G25={v25_u8} delta={v25_u8 - v51_u8}")
        if length >= 2:
            v51_be = int.from_bytes(GAMER51[s:s+2], "big")
            v25_be = int.from_bytes(GAMER25[s:s+2], "big")
            v51_le = int.from_bytes(GAMER51[s:s+2], "little")
            v25_le = int.from_bytes(GAMER25[s:s+2], "little")
            print(f"    u16@{s:#x} BE: G51={v51_be} G25={v25_be} delta={v25_be - v51_be}")
            print(f"    u16@{s:#x} LE: G51={v51_le} G25={v25_le} delta={v25_le - v51_le}")
        if length >= 4:
            v51_be = int.from_bytes(GAMER51[s:s+4], "big")
            v25_be = int.from_bytes(GAMER25[s:s+4], "big")
            v51_le = int.from_bytes(GAMER51[s:s+4], "little")
            v25_le = int.from_bytes(GAMER25[s:s+4], "little")
            print(f"    u32@{s:#x} BE: G51={v51_be} G25={v25_be} delta={v25_be - v51_be}")
            print(f"    u32@{s:#x} LE: G51={v51_le} G25={v25_le} delta={v25_le - v51_le}")

# === World-state diffs — summary of largest ranges (likely position/state, not inventory) ===
print()
print("=" * 75)
print("WORLD-STATE DIFFS (outside known corrupt regions; first 30 by offset)")
print("=" * 75)
for i, (s, e) in enumerate(world_ranges[:30]):
    length = e - s + 1
    g51h = GAMER51[s:e+1].hex(" ")
    g25h = GAMER25[s:e+1].hex(" ")
    if len(g51h) > 56:
        g51h = g51h[:53] + "..."
    if len(g25h) > 56:
        g25h = g25h[:53] + "..."
    print(f"  #{i:>3} @{s:#10x}  len={length:<4}  G51: {g51h}")
    print(f"                                  G25: {g25h}")
print()
print(f"  ... total world-state non-corrupt diff ranges: {len(world_ranges)}")
