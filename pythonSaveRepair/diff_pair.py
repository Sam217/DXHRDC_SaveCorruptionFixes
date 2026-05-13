"""Generic byte-diff between two save files. Reports:

 - area name strings at offset 0x5045 (helps confirm same-area pair)
 - all contiguous differing ranges (gap <= 8 collapses)
 - bucketing: progression header (<0xF0000) vs world state (>=0xF0000)
 - full hex+ASCII context for progression-header ranges
 - top-N largest world-state ranges + a stack/heap-pointer sniff per range

Usage:  python pythonSaveRepair/diff_pair.py GAMER51_4 GAMER53_4
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from save_repair_tool import read_save  # noqa: E402

SAVES = os.path.normpath(os.path.join(HERE, "..", "238010", "remote"))
PROG_BOUNDARY = 0xF0000

STACK_LO, STACK_HI = 0x02000000, 0x0FFFFFFF
HEAP_LO, HEAP_HI = 0x10000000, 0x1FFFFFFF


def area_name(buf: bytes, off: int = 0x5045, max_len: int = 64) -> str:
    chunk = buf[off:off + max_len]
    end = chunk.find(b"\x00")
    if end == -1:
        end = max_len
    return chunk[:end].decode("ascii", errors="replace")


def collapse(diffs, gap=8):
    if not diffs:
        return []
    ranges = []
    start = diffs[0]
    prev = diffs[0]
    for off in diffs[1:]:
        if off - prev <= gap:
            prev = off
        else:
            ranges.append((start, prev))
            start = off
            prev = off
    ranges.append((start, prev))
    return ranges


def sniff_pointers_le(buf: bytes, s: int, e: int):
    """Count uint32 LE values in buf[s..e] that fall in stack/heap windows."""
    stack = heap = 0
    # Scan from s aligned to 4
    a4 = s & ~3
    for off in range(a4, e + 1 - 3, 4):
        v = int.from_bytes(buf[off:off + 4], "little")
        if STACK_LO <= v <= STACK_HI:
            stack += 1
        elif HEAP_LO <= v <= HEAP_HI:
            heap += 1
    return stack, heap


def show(buf, off, label, length):
    sub = buf[off:off + length]
    ascii_repr = "".join(chr(c) if 32 <= c < 127 else "." for c in sub)
    print(f"  {label} @{off:#x}: {sub.hex(' ')}")
    print(f"  {label} ascii  : {ascii_repr}")


def main():
    if len(sys.argv) != 3:
        print("Usage: diff_pair.py <save_a> <save_b>")
        sys.exit(1)

    name_a, name_b = sys.argv[1], sys.argv[2]
    a = read_save(os.path.join(SAVES, name_a))
    b = read_save(os.path.join(SAVES, name_b))
    assert len(a) == len(b)

    area_a = area_name(a)
    area_b = area_name(b)
    print(f"{name_a} area: {area_a!r}")
    print(f"{name_b} area: {area_b!r}")
    print(f"Same area: {area_a == area_b}")
    print()

    diffs = [i for i in range(len(a)) if a[i] != b[i]]
    print(f"Total differing bytes: {len(diffs):,}  ({100*len(diffs)/len(a):.3f}%)")

    ranges = collapse(diffs, gap=8)
    print(f"Contiguous ranges (gap<=8): {len(ranges)}")

    prog = [r for r in ranges if r[1] < PROG_BOUNDARY]
    world = [r for r in ranges if r[0] >= PROG_BOUNDARY]
    straddle = [r for r in ranges if r[0] < PROG_BOUNDARY <= r[1]]
    print(f"  progression header  (<{PROG_BOUNDARY:#x}): {len(prog)}")
    print(f"  world state         (>={PROG_BOUNDARY:#x}): {len(world)}")
    print(f"  straddling boundary                : {len(straddle)}")
    print()

    # --- progression-header ranges: full context ---
    if prog:
        print(f"=== {len(prog)} progression-header ranges (full context) ===\n")
        for i, (s, e) in enumerate(prog):
            length = e - s + 1
            ctx_lo = max(0, s - 16)
            ctx_hi = min(len(a), e + 17)
            print(f"--- prog #{i}: {s:#x}-{e:#x} (len={length}) ---")
            show(a, ctx_lo, name_a, ctx_hi - ctx_lo)
            show(b, ctx_lo, name_b, ctx_hi - ctx_lo)
            print()

    # --- world-state ranges: top 15 by size, with pointer sniff ---
    if world:
        print(f"=== Top 15 world-state ranges (by length) with stack/heap sniff ===\n")
        big = sorted(world, key=lambda r: -(r[1] - r[0]))[:15]
        print(f"{'#':>3} {'offset':>10} {'len':>8}  {'A stack':>8} {'A heap':>8} {'B stack':>8} {'B heap':>8}")
        for i, (s, e) in enumerate(big):
            length = e - s + 1
            sa, ha = sniff_pointers_le(a, s, e)
            sb, hb = sniff_pointers_le(b, s, e)
            print(f"{i:>3} {s:>#10x} {length:>8}  {sa:>8} {ha:>8} {sb:>8} {hb:>8}")
        print()

        # Whole-buffer pointer counts as a baseline
        a_s, a_h = sniff_pointers_le(a, PROG_BOUNDARY, len(a) - 1)
        b_s, b_h = sniff_pointers_le(b, PROG_BOUNDARY, len(b) - 1)
        print(f"Whole world-state stack-range uint32 LE count:  {name_a}={a_s:,}   {name_b}={b_s:,}")
        print(f"Whole world-state heap-range  uint32 LE count:  {name_a}={a_h:,}   {name_b}={b_h:,}")
        print()

        # Show first 20 world-state ranges with hex context (limited)
        print(f"=== First 20 world-state ranges (offset-ordered, hex preview) ===\n")
        for i, (s, e) in enumerate(world[:20]):
            length = e - s + 1
            ah = a[s:e + 1].hex(' ')
            bh = b[s:e + 1].hex(' ')
            if len(ah) > 60:
                ah = ah[:57] + '...'
            if len(bh) > 60:
                bh = bh[:57] + '...'
            sa, ha = sniff_pointers_le(a, s, e)
            sb, hb = sniff_pointers_le(b, s, e)
            print(f"#{i:>3} {s:>#10x} len={length:<5} stk/hp: A={sa}/{ha} B={sb}/{hb}")
            print(f"     A: {ah}")
            print(f"     B: {bh}")


if __name__ == "__main__":
    main()
