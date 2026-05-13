"""Drill into the two suspect world-state regions identified by diff_pair.py
and find the painkiller count change (4 -> 12) as a controlled-experiment check.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from save_repair_tool import read_save  # noqa: E402

SAVES = os.path.normpath(os.path.join(HERE, "..", "238010", "remote"))

a = read_save(os.path.join(SAVES, "GAMER51_4"))  # clean
b = read_save(os.path.join(SAVES, "GAMER25_4"))  # corrupt, 15m later, painkillers hacked 4->12


def zero_density(buf: bytes, lo: int, hi: int, window: int = 1024) -> list:
    """For each `window`-byte chunk in [lo, hi), return fraction of zero bytes."""
    out = []
    for off in range(lo, hi, window):
        chunk = buf[off:off + window]
        if not chunk:
            break
        z = chunk.count(0) / len(chunk)
        out.append((off, z))
    return out


def show_byte_class(buf: bytes, lo: int, hi: int, window: int = 2048):
    """Print per-window summary of byte categories."""
    print(f"  {'offset':>10} {'%zero':>6} {'%FF':>6} {'%print':>6}")
    for off in range(lo, hi, window):
        chunk = buf[off:off + window]
        if not chunk:
            break
        z = chunk.count(0) / len(chunk) * 100
        f = chunk.count(0xFF) / len(chunk) * 100
        p = sum(1 for c in chunk if 32 <= c < 127) / len(chunk) * 100
        print(f"  {off:>#10x} {z:>6.1f} {f:>6.1f} {p:>6.1f}")


# === Suspect region #1: 0x1f8a6f, length 96421 ===
print("=" * 70)
print("SUSPECT REGION #1: 0x1f8a6f .. 0x210594 (length 96,421)")
print("=" * 70)
print("\n--- GAMER51 (clean) ---")
show_byte_class(a, 0x1f8a6f, 0x1f8a6f + 96421)
print("\n--- GAMER25 (corrupt) ---")
show_byte_class(b, 0x1f8a6f, 0x1f8a6f + 96421)

# === Suspect region #3: 0x211355, length 24451 ===
print("\n" + "=" * 70)
print("SUSPECT REGION #3: 0x211355 .. 0x217298 (length 24,451)")
print("=" * 70)
print("\n--- GAMER51 (clean) ---")
show_byte_class(a, 0x211355, 0x211355 + 24451)
print("\n--- GAMER25 (corrupt) ---")
show_byte_class(b, 0x211355, 0x211355 + 24451)

# === Painkiller count change: 4 -> 12 ===
# In CheatEngine the value was uint16 LE in memory.
# On disk it should be uint16 BE if dnSpy format is right.
# Check both endiannesses.
print("\n" + "=" * 70)
print("PAINKILLER COUNT CHANGE SEARCH (4 -> 12)")
print("=" * 70)

# In GAMER51, painkiller count was 4 (before hack). In GAMER25, it should be 12.
# Look for offsets where GAMER51 has the value 4 and GAMER25 has 12 (BE or LE, 16-bit aligned and unaligned).
PK_ID = bytes.fromhex("001F51")  # Painkillers per form1.cs


def find_pk_records(buf: bytes, label: str):
    """Find every occurrence of the Painkillers ID and show surrounding bytes
    plus what could be a count (BE/LE uint16 at +3..+8)."""
    print(f"\n  --- {label} ---")
    idxs = []
    pos = 0
    while True:
        i = buf.find(PK_ID, pos)
        if i == -1:
            break
        idxs.append(i)
        pos = i + 1
    print(f"  found {len(idxs)} occurrences of 00 1F 51")
    for i in idxs[:30]:
        ctx = buf[max(0, i - 4):i + 16]
        # Try interpreting bytes after ID as uint16
        if i + 8 < len(buf):
            be3 = int.from_bytes(buf[i + 3:i + 5], "big")
            le3 = int.from_bytes(buf[i + 3:i + 5], "little")
            be5 = int.from_bytes(buf[i + 5:i + 7], "big")
            le5 = int.from_bytes(buf[i + 5:i + 7], "little")
            be6 = int.from_bytes(buf[i + 6:i + 8], "big")
            le6 = int.from_bytes(buf[i + 6:i + 8], "little")
            print(f"  @{i:#08x}  ctx={ctx.hex(' ')}  "
                  f"u16@+3 BE={be3} LE={le3}  "
                  f"u16@+5 BE={be5} LE={le5}  "
                  f"u16@+6 BE={be6} LE={le6}")


find_pk_records(a, "GAMER51 (count=4 expected)")
find_pk_records(b, "GAMER25 (count=12 expected)")

# Now find every position where GAMER51 has u16=4 and GAMER25 has u16=12 (or vice versa)
# in the WHOLE buffer — a more aggressive sweep.
print("\n  --- Targeted sweep: offsets where (GAMER51=4, GAMER25=12) as uint16 ---")
for endian in ("big", "little"):
    print(f"\n    Endian = {endian}")
    hits = []
    for off in range(0, len(a) - 1):
        va = int.from_bytes(a[off:off + 2], endian)
        vb = int.from_bytes(b[off:off + 2], endian)
        if va == 4 and vb == 12:
            hits.append(off)
            if len(hits) > 200:
                break
    print(f"    {len(hits)} offsets where (51,25) = (4,12) as u16 {endian}")
    # Show the ones in progression header
    prog = [h for h in hits if h < 0xF0000]
    print(f"    in progression header: {len(prog)}")
    for h in prog[:20]:
        ctx_a = a[max(0, h - 6):h + 10]
        ctx_b = b[max(0, h - 6):h + 10]
        print(f"      @{h:#08x}  A={ctx_a.hex(' ')}  B={ctx_b.hex(' ')}")
