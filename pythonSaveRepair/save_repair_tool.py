"""
DXHR:DC Save Repair Tool

Background and findings:
  - PC saves are zlib-compressed (magic 78 9C), decompress to a fixed
    0x23A000-byte buffer matching the engine's allocation.
  - The first 960 KB (0x000000-0x0F0000) is "player progression" — it
    is essentially identical between consecutive saves in the same
    chapter (only ~160 bytes differ in observed pair).
  - The remaining 1.4 MB (0x0F0000-0x23A000) is "per-session world
    state" (instances, NPC positions, ragdolls). This is where the
    save corruption lives.

Experiment 1 (this script's default mode):

  Graft a "broken" save's progression header onto a "working" save's
  world state. If the resulting hybrid loads cleanly into the working
  save's location while preserving any progression diff from the
  broken save, that confirms the corruption is bounded to the
  world-state region — and a real surgical-repair tool becomes
  feasible. If it crashes, the corruption boundaries differ from our
  current model and we need to remap.

Usage:
  python save_repair_tool.py            # use built-in defaults
  python save_repair_tool.py --help     # show all options
  python save_repair_tool.py \
      --broken GAMER23_4 \
      --working GAMER63_4 \
      --output GAMER22_4 \
      --boundary 0xF0000

Safety:
  - The output file is ALWAYS backed up first as
    <output>_pre_repair_<timestamp> so the original can be restored.
  - The script never touches the input files.
"""

import argparse
import os
import shutil
import sys
import time
import zlib

# Default in-repo locations (junction -> Steam userdata).
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_SAVES_DIR = os.path.join(REPO_ROOT, "238010", "remote")

# Decompressed PC save size (matches engine's FUN_001ac850(0x23A000)).
DECOMP_SIZE = 0x23A000

# Default boundary between "progression header" and "world state".
# Empirical (from GAMER23 vs GAMER63 diff): only 160 bytes diff in the
# first 0xF0000, vs 50-95% diff per 16KB chunk after.
DEFAULT_BOUNDARY = 0xF0000


def read_save(path: str) -> bytes:
    """Read and zlib-decompress a save file. Validate decompressed size."""
    with open(path, "rb") as f:
        compressed = f.read()
    # PC saves should start with zlib magic 78 9C.
    if len(compressed) < 2 or compressed[:2] != b"\x78\x9c":
        raise ValueError(
            f"{path}: not a zlib-compressed PC save "
            f"(first 2 bytes: {compressed[:2].hex() if compressed else 'empty'})"
        )
    decompressed = zlib.decompress(compressed)
    if len(decompressed) != DECOMP_SIZE:
        raise ValueError(
            f"{path}: decompressed size {len(decompressed):#x} "
            f"!= expected {DECOMP_SIZE:#x}"
        )
    return decompressed


def write_save(path: str, decompressed: bytes) -> None:
    """zlib-compress (default level, magic 78 9C) and write to path."""
    if len(decompressed) != DECOMP_SIZE:
        raise ValueError(
            f"output buffer size {len(decompressed):#x} "
            f"!= expected {DECOMP_SIZE:#x}"
        )
    # zlib default level = 6, produces 78 9C magic — matches what the
    # engine writes.
    compressed = zlib.compress(decompressed, level=6)
    with open(path, "wb") as f:
        f.write(compressed)


def hybrid_graft(broken: bytes, working: bytes, boundary: int) -> bytes:
    """
    Combine: broken[:boundary] + working[boundary:].

    Use the broken save's progression header (preserving any progression
    diffs) and the working save's per-session world state (which is
    known to load cleanly).
    """
    if len(broken) != DECOMP_SIZE or len(working) != DECOMP_SIZE:
        raise ValueError("inputs must be DECOMP_SIZE bytes")
    if not (0 < boundary < DECOMP_SIZE):
        raise ValueError(f"boundary {boundary:#x} out of range")
    return broken[:boundary] + working[boundary:]


def diff_summary(a: bytes, b: bytes, label_a: str, label_b: str) -> None:
    """Print a quick byte-diff summary between two equal-length buffers."""
    if len(a) != len(b):
        print(f"  size mismatch: {label_a}={len(a):#x} vs {label_b}={len(b):#x}")
        return
    n = sum(1 for x, y in zip(a, b) if x != y)
    print(
        f"  {label_a} vs {label_b}: "
        f"{n:,} bytes differ ({100*n/len(a):.2f}%)"
    )


def backup_file(path: str) -> str:
    """Copy `path` to a timestamped backup. Returns the backup path."""
    if not os.path.isfile(path):
        return ""  # nothing to backup
    ts = time.strftime("%Y%m%d_%H%M%S")
    bak = f"{path}_pre_repair_{ts}"
    shutil.copy2(path, bak)
    return bak


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--saves-dir", default=DEFAULT_SAVES_DIR,
                    help="folder containing GAMER##_4 files "
                         f"(default: {DEFAULT_SAVES_DIR})")
    ap.add_argument("--broken", default="GAMER23_4",
                    help="broken save (progression source) (default: GAMER23_4)")
    ap.add_argument("--working", default="GAMER63_4",
                    help="working save (world-state source) (default: GAMER63_4)")
    ap.add_argument("--output", default="GAMER22_4",
                    help="slot to overwrite with hybrid (default: GAMER22_4)")
    ap.add_argument("--boundary", default=hex(DEFAULT_BOUNDARY),
                    help=f"byte offset separating progression from world state "
                         f"(default: {DEFAULT_BOUNDARY:#x})")
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would happen without writing anything")
    args = ap.parse_args()

    boundary = int(args.boundary, 0)
    broken_path = os.path.join(args.saves_dir, args.broken)
    working_path = os.path.join(args.saves_dir, args.working)
    output_path = os.path.join(args.saves_dir, args.output)

    print(f"saves dir : {args.saves_dir}")
    print(f"broken    : {broken_path}")
    print(f"working   : {working_path}")
    print(f"output    : {output_path}")
    print(f"boundary  : {boundary:#x} ({boundary:,} bytes)")
    print()

    print("Reading inputs...")
    broken = read_save(broken_path)
    working = read_save(working_path)
    print(f"  broken decompressed: {len(broken):#x} bytes ({len(broken):,})")
    print(f"  working decompressed: {len(working):#x} bytes ({len(working):,})")
    print()

    print("Diff overview:")
    diff_summary(broken, working, "broken", "working")
    diff_summary(broken[:boundary], working[:boundary],
                  f"broken[:{boundary:#x}]", f"working[:{boundary:#x}]")
    diff_summary(broken[boundary:], working[boundary:],
                  f"broken[{boundary:#x}:]", f"working[{boundary:#x}:]")
    print()

    print("Building hybrid...")
    hybrid = hybrid_graft(broken, working, boundary)
    print(f"  hybrid size: {len(hybrid):#x} bytes")
    print()

    print("Sanity check on hybrid:")
    diff_summary(hybrid, broken, "hybrid", "broken")
    diff_summary(hybrid, working, "hybrid", "working")
    print()

    if args.dry_run:
        print("DRY RUN — not writing anything.")
        return

    bak = backup_file(output_path)
    if bak:
        print(f"Backed up existing {args.output} -> {os.path.basename(bak)}")
    else:
        print(f"No existing {args.output} to back up (will create new file).")

    print(f"Writing hybrid -> {output_path}")
    write_save(output_path, hybrid)
    print(f"  wrote {os.path.getsize(output_path):,} compressed bytes")
    print()

    # Roundtrip verification: re-read what we wrote, compare to hybrid.
    print("Verifying roundtrip (decompress what we wrote, compare to hybrid)...")
    rt = read_save(output_path)
    if rt == hybrid:
        print("  OK: decompressed output matches hybrid byte-for-byte.")
    else:
        n = sum(1 for x, y in zip(rt, hybrid) if x != y)
        print(f"  FAIL: roundtrip differs in {n} bytes (CRITICAL — investigate)")
        sys.exit(1)

    print()
    print("Done. Now load the slot in-game with our hooks installed.")
    print("Watch dxhr_memfix.log for hook activity.")
    print()
    print(f"To restore the original {args.output}, copy {os.path.basename(bak)} back.")


if __name__ == "__main__":
    main()
