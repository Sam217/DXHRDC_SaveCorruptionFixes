"""Re-read area names from the correct offset (0x503c), showing both the
extracted string and the raw hex framing so we can verify nothing is
being guessed or labelled beyond what's actually in the file.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from save_repair_tool import read_save  # noqa: E402

SAVES = os.path.normpath(os.path.join(HERE, "..", "238010", "remote"))


def load(name):
    return read_save(os.path.join(SAVES, name))


def extract_strings(buf, lo=0x5030, hi=0x5080):
    """Walk the bytes in [lo, hi), splitting on null bytes, return all
    non-empty ASCII strings of length >= 2."""
    chunk = buf[lo:hi]
    parts = chunk.split(b"\x00")
    return [p.decode("latin-1", errors="replace") for p in parts
            if len(p) >= 2 and all(32 <= c < 127 for c in p)]


# Sample a wide variety of saves, focusing on the ones the user mentioned.
samples = [
    "GAMER1_4", "GAMER5_4", "GAMER6_4", "GAMER10_4", "GAMER20_4",
    "GAMER22_4", "GAMER23_4", "GAMER24_4", "GAMER25_4", "GAMER26_4",
    "GAMER50_4", "GAMER51_4", "GAMER53_4", "GAMER63_4", "GAMER83_4",
    "GAMEA1_4", "GAMEA2_4", "GAMEQ1_4",
]

print("Raw bytes 0x5030..0x5080, plus every non-empty ASCII string found in that span.")
print("No chapter interpretation — only what's literally in the file.\n")

for n in samples:
    try:
        buf = load(n)
    except Exception as e:
        print(f"{n:<14}  SKIP: {e}")
        continue
    hexs = buf[0x5030:0x5080].hex(" ")
    asc = "".join(chr(c) if 32 <= c < 127 else "." for c in buf[0x5030:0x5080])
    strings = extract_strings(buf)
    print(f"{n:<14}")
    print(f"  hex  : {hexs}")
    print(f"  ascii: {asc}")
    print(f"  strings found: {strings}")
    print()
