"""
DXHR:DC Save Repair Tool

Background:
  - PC saves are zlib-compressed (magic 78 9C), decompress to a fixed
    0x23A000-byte buffer matching the engine's allocation.
  - First 960 KB (0x000000-0x0F0000) = player progression header.
  - Remaining 1.4 MB (0x0F0000-0x23A000) = per-session world state
    where the corruption lives.

Modes:

  --mode=hybrid (default; non-viable per SUMMARY §11.1, kept for repro)
    Graft broken[:boundary] + working[boundary:] -> output slot.

  --mode=scan
    Scan one save (--input NAME) or all saves (--scan-all) for uint32s
    that fall in the user-mode stack range (0x02000000-0x0FFFFFFF) or
    the heap range (0x10000000-0x1FFFFFFF). FALSIFIED as a corruption
    detector: every save (including known-clean GAMER51) has 14-29k
    hits in world state from legitimate engine data. Kept for forensics.

  --mode=scan-anomalies
    Scan world state for the byte-class signature of the runaway writer
    (per SUMMARY §11.2): 2KB window with %zero in [22, 30] AND %print
    in [22, 30] — the writer dumping 4-byte values from contiguous
    uninitialized memory (in GAMER25 produces the tight 25.0%/25.0%
    core at 0x1fb26f). Adjacent flagged windows merge into regions.
    Clean saves (GAMER51 baseline: 42-56% zero, 0-22% printable) hit
    nothing. The %FF axis is NOT distinctive — normal world state has
    3-7% FF too — so it's not part of the detector.

Usage:
  python save_repair_tool.py --mode=scan --scan-all
  python save_repair_tool.py --mode=scan-anomalies --scan-all
  python save_repair_tool.py --mode=scan-anomalies --input GAMER25_4
  python save_repair_tool.py --mode=hybrid --broken GAMER23_4 --working GAMER63_4

Safety:
  - Hybrid mode backs up the output slot as <output>_pre_repair_<ts>.
  - Scan mode is read-only.
"""

import argparse
import os
import re
import shutil
import struct
import sys
import time
import zlib
from collections import Counter

# Default in-repo locations (junction -> Steam userdata).
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
# print(f"Repo root: {REPO_ROOT}")
DEFAULT_SAVES_DIR = os.path.join(REPO_ROOT, "238010", "remote")

# Decompressed PC save size (matches engine's FUN_001ac850(0x23A000)).
DECOMP_SIZE = 0x23A000

# Default boundary between "progression header" and "world state".
# Empirical (from GAMER23 vs GAMER63 diff): only 160 bytes diff in the
# first 0xF0000, vs 50-95% diff per 16KB chunk after.
DEFAULT_BOUNDARY = 0xF0000

# User-mode 32-bit stack pages. Per SUMMARY §10.4 the corrupted counts
# observed in deserialization (45M, 13M, 5M...) all sit here, and the
# crash registers correlated tightly with this range — uninitialized
# stack values are leaking into InstanceTable->field_0x14 at save time.
STACK_RANGE = (0x02000000, 0x0FFFFFFF)

# dlmalloc primary heap range (engine reserves 512 MB starting near
# 0x10000000, optionally patched up to 1.5 GB by patch_heap_size.py).
# Secondary diagnostic — heap pointers in a save buffer are also
# unambiguously corrupt.
HEAP_RANGE = (0x10000000, 0x1FFFFFFF)

# Chunk size for grouping scan hits (16 KB).
DEFAULT_CHUNK_SIZE = 0x4000

# Default cap on per-save "top candidates" detail listing.
DEFAULT_TOP_N = 20

# --- byte-class anomaly detection (scan-anomalies) ---
# The runaway writer's output is bit-for-bit uniform ~25%/25% across 2KB
# windows in the corrupted region (SUMMARY §11.2 / analyze_suspect_regions
# output for GAMER25 0x1fb26f..0x202a6f). Clean saves in the same region
# show 42-56% zero, 0-22% printable. The %FF axis is NOT distinctive —
# normal world state has 3-7% FF too — so we only detect Signature A.
ANOMALY_WINDOW = 0x800   # 2 KB
ANOMALY_STEP = 0x400   # 1 KB (50% overlap)
RUNAWAY_ZERO_LO, RUNAWAY_ZERO_HI = 22.0, 30.0
RUNAWAY_PRINT_LO, RUNAWAY_PRINT_HI = 22.0, 30.0

# Strict save-file name regex: GAMER##_4, GAMEA##_4, GAMEQ##_4. Excludes
# *_Backup, *.bak, *_pre_repair_*, "* - Copy" etc.
SAVE_FILE_RE = re.compile(r"^GAME[RAQ]\d+_4$")

# XP/Praxis snapshot anchor: 12-byte sequence containing 3 stable item-IDs
# that occur near the player's exp+praxis fields. From form1.cs
# CacheOffsets() — at each match, XP = BE int32 at (offset - 12) and
# praxis = BE int32 at (offset - 8). The editor finds 4 redundant copies.
XP_PRAXIS_MAGIC = bytes.fromhex("00012D7500012D8300012D7B")

# PC Inventory items: (4-byte hex ID LE, friendly name).
# Inferred from differential analysis of PC saves.
# Record layout (minimum 20 bytes):
#   [0..3]: ID (4 bytes LE)
#   [4..5]: Flag (2 bytes LE, usually 1)
#   [6..7]: count (2 bytes LE uint16)
#   [8..11]: Grid X (4 bytes LE)
#   [12..15]: Grid Y (4 bytes LE)
#   [16..19]: Rotation / Status (4 bytes LE signed int)
INVENTORY_ITEMS = [
    ("6a260000", "Painkillers"),
    ("e52c0000", "CyberBoost_ProEnergy"),
    ("58260000", "CyberBoost_ProEnergy_Pack"),
    ("1b4d0000", "CyberBoost_ProEnergy_Jar"),
    ("0b2c0100", "Vodka"),
    ("a3c20000", "Auto_Unlock_Device"),
    ("b92c0000", "Nuke_Virus"),
    ("f42d0000", "Stop_Worm"),
    ("49290000", "FR27_Auto_Rifle_Silenced"),
    ("14ff0000", "Grenade_Launcher"),
    ("f11e0000", "10mm_Pistol_Upgraded"),
    ("019a0000", "Tranquilizer_Rifle_Upgraded"),
    ("72210000", "Combat_Rifle_Ammo"),
    ("335f0000", "Typhoon_Ammo"),
    ("6c2e0000", "Tranquilizer_Darts"),
    ("08ff0000", "Grenade_Launcher_Ammo"),
    ("fc050000", "10mm_Pistol_Ammo"),
    ("3d290000", "Ammo_Upgrade"),
    ("68600000", "Laser_Targeting_Upgrade"),
    ("cb1c0000", "Sticky_Mine"),
    ("fd050000", "Frag_Grenade"),
    ("fe050000", "Flash_Bang"),
    ("e0590000", "EMP_Grenade"),
    ("df590000", "EMP_Mine"),
    ("a3720000", "Remote_Detonated_Explosive"),
]

# Inventory section header: [u32 gridWidth=14] [u32 gridHeight=7] [u16 itemCount]
# followed by itemCount x 40-byte records.  Validated across all 100+ save files.
# The header floats to different offsets per save (variable-length stream).
INVENTORY_HEADER = b"\x0e\x00\x00\x00\x07\x00\x00\x00"  # u32(14) + u32(7)
INVENTORY_RECORD_SIZE = 40  # 0x28 bytes per item
INVENTORY_GRID_WIDTH = 14
INVENTORY_GRID_HEIGHT = 7

# Reverse lookup: item ID (int) -> friendly name
INVENTORY_ID_TO_NAME = {}
for _hex, _name in INVENTORY_ITEMS:
    _id_val = int.from_bytes(bytes.fromhex(_hex), 'little')
    INVENTORY_ID_TO_NAME[_id_val] = _name


def read_save(path: str) -> bytes:
    """Read a save file (zlib-compressed or raw .dec). Validate decompressed size."""
    with open(path, "rb") as f:
        raw = f.read()
    # Already decompressed?  Accept it directly.
    if len(raw) == DECOMP_SIZE:
        return raw
    # PC saves should start with zlib magic 78 9C.
    if len(raw) < 2 or raw[:2] != b"\x78\x9c":
        raise ValueError(
            f"{path}: not a zlib-compressed PC save and not a raw .dec "
            f"(size={len(raw):#x}, first 2 bytes: {raw[:2].hex() if raw else 'empty'})"
        )
    decompressed = zlib.decompress(raw)
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
        print(
            f"  size mismatch: {label_a}={len(a):#x} vs {label_b}={len(b):#x}")
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


def list_save_files(saves_dir: str):
    """Return [(name, path, mtime), ...] for every regular GAME[RAQ]##_4 file."""
    out = []
    for name in os.listdir(saves_dir):
        if not SAVE_FILE_RE.match(name):
            continue
        path = os.path.join(saves_dir, name)
        if not os.path.isfile(path):
            continue
        out.append((name, path, os.path.getmtime(path)))
    return out


def scan_uint32_in_range(buf: bytes, lo: int, hi: int):
    """Yield (offset, value) for every aligned uint32 LE in [lo, hi]."""
    end = len(buf) - (len(buf) % 4)
    for off in range(0, end, 4):
        v = struct.unpack_from("<I", buf, off)[0]
        if lo <= v <= hi:
            yield off, v


def scan_buffer_summary(buf: bytes, boundary: int = DEFAULT_BOUNDARY):
    """Return dict of per-range hit lists and counts. Cheap; no printing."""
    return {
        "stack": list(scan_uint32_in_range(buf, *STACK_RANGE)),
        "heap":  list(scan_uint32_in_range(buf, *HEAP_RANGE)),
        "boundary": boundary,
        "size": len(buf),
    }


def _hex_ctx(buf: bytes, off: int, before: int = 8, after: int = 12) -> str:
    """Render hex bytes around `off`, bracketing the 4 bytes at `off`."""
    a = max(0, off - before)
    b = min(len(buf), off + 4 + after)
    pre = buf[a:off].hex(" ")
    cur = buf[off:off+4].hex(" ")
    post = buf[off+4:b].hex(" ")
    return f"{pre} [{cur}] {post}"


def print_scan_detail(buf: bytes, name: str, summary: dict, top_n: int, chunk_size: int):
    """Print the per-save scan detail (chunk histogram + top candidates)."""
    print(f"=== scan: {name} ===")
    print(f"  buffer size : {summary['size']:#x} ({summary['size']:,} bytes)")
    boundary = summary["boundary"]

    for label, (lo, hi), key in (
        ("STACK", STACK_RANGE, "stack"),
        ("HEAP",  HEAP_RANGE,  "heap"),
    ):
        hits = summary[key]
        in_prog = sum(1 for off, _ in hits if off < boundary)
        in_world = sum(1 for off, _ in hits if off >= boundary)
        print()
        print(f"  {label}-range uint32s ({lo:#010x} - {hi:#010x}):")
        print(f"    total hits           : {len(hits)}")
        print(
            f"    in progression header: {in_prog}  (offset < {boundary:#x})")
        print(
            f"    in world state       : {in_world}  (offset >= {boundary:#x})")
        if not hits:
            continue

        by_chunk = Counter((off // chunk_size) * chunk_size for off, _ in hits)
        print(
            f"    per-chunk counts (chunk size {chunk_size:#x}, only chunks with hits):")
        for chunk_off in sorted(by_chunk):
            region = "PROG " if chunk_off < boundary else "WORLD"
            print(
                f"      {chunk_off:#08x}  [{region}]  hits: {by_chunk[chunk_off]}")

        n = min(top_n, len(hits))
        print(f"    top {n} candidates by offset:")
        for off, v in hits[:n]:
            region = "PROG " if off < boundary else "WORLD"
            print(
                f"      [{off:#08x} {region}] val={v:#010x}  ctx: {_hex_ctx(buf, off)}")


def find_all(buf: bytes, needle: bytes):
    """Yield every offset of `needle` in `buf` (non-overlapping)."""
    i = 0
    while True:
        idx = buf.find(needle, i)
        if idx < 0:
            return
        yield idx
        i = idx + 1  # allow overlapping matches; not strictly needed here


def read_be_int32(buf: bytes, off: int) -> int:
    """Big-endian signed int32. The Xbox 360 editor uses Endian.Big throughout."""
    return struct.unpack_from(">i", buf, off)[0]


def read_be_uint16(buf: bytes, off: int) -> int:
    """Big-endian unsigned int16. Inventory counts use this encoding."""
    return struct.unpack_from(">H", buf, off)[0]


def find_inventory_sections(buf: bytes) -> list:
    """Find all inventory sections in a decompressed save buffer.

    Searches for the inventory header pattern:
        [u32 gridWidth=14] [u32 gridHeight=7] [u16 itemCount]
    followed by itemCount x 40-byte item records.

    Returns a list of dicts, each shaped like:
      {
        "header_off": int,       # offset of the header (gridWidth field)
        "items_off": int,        # offset of first item record
        "item_count": int,       # number of items
        "grid_width": int,       # always 14
        "grid_height": int,      # always 7
        "items": [
          {
            "item_id": int,      # raw item ID
            "id_hex": str,       # 4-byte LE hex string
            "name": str,         # friendly name or "Unknown_0xXXXX"
            "flag": int,         # usually 1 or 257
            "count": int,        # stack count
            "pos_x": int,        # grid column (0-13)
            "pos_y": int,        # grid row (0-6)
            "rotation": int,     # rotation / sort-order state
            "extra": bytes,      # 20 bytes of upgrade/attachment data
            "off": int,          # absolute offset in the buffer
          }, ...
        ],
      }
    """
    sections = []
    pos = 0
    while True:
        idx = buf.find(INVENTORY_HEADER, pos)
        if idx < 0:
            break

        # Read u16 item count immediately after the 8-byte header
        count_off = idx + 8
        if count_off + 2 > len(buf):
            pos = idx + 1
            continue

        item_count = struct.unpack_from("<H", buf, count_off)[0]

        # Sanity: count must be reasonable (0-500) and data must fit
        items_off = count_off + 2  # first item record
        end_off = items_off + item_count * INVENTORY_RECORD_SIZE
        if item_count > 500 or end_off > len(buf):
            pos = idx + 1
            continue

        # Validate: at least the first item should look plausible
        if item_count > 0:
            flag0 = struct.unpack_from("<H", buf, items_off + 4)[0]
            px0 = struct.unpack_from("<I", buf, items_off + 8)[0]
            py0 = struct.unpack_from("<I", buf, items_off + 12)[0]
            if flag0 not in (0, 1, 257) or px0 >= 20 or py0 >= 10:
                pos = idx + 1
                continue

        # Parse all item records
        items = []
        for i in range(item_count):
            rec_off = items_off + i * INVENTORY_RECORD_SIZE
            item_id = struct.unpack_from("<I", buf, rec_off)[0]
            flag    = struct.unpack_from("<H", buf, rec_off + 4)[0]
            count   = struct.unpack_from("<H", buf, rec_off + 6)[0]
            px      = struct.unpack_from("<I", buf, rec_off + 8)[0]
            py      = struct.unpack_from("<I", buf, rec_off + 12)[0]
            rot     = struct.unpack_from("<i", buf, rec_off + 16)[0]
            extra   = buf[rec_off + 20 : rec_off + INVENTORY_RECORD_SIZE]

            id_hex = buf[rec_off:rec_off+4].hex()
            name = INVENTORY_ID_TO_NAME.get(item_id, f"Unknown_0x{item_id:04X}")

            items.append({
                "item_id": item_id,
                "id_hex": id_hex,
                "name": name,
                "flag": flag,
                "count": count,
                "pos_x": px,
                "pos_y": py,
                "rotation": rot,
                "extra": extra,
                "off": rec_off,
            })

        sections.append({
            "header_off": idx,
            "items_off": items_off,
            "item_count": item_count,
            "grid_width": INVENTORY_GRID_WIDTH,
            "grid_height": INVENTORY_GRID_HEIGHT,
            "items": items,
        })

        # Skip past this section to find the next one
        pos = end_off

    return sections


def read_progression(buf: bytes) -> dict:
    """Read XP/praxis snapshots and inventory sections from a decompressed save.

    Returns a dict shaped like:
      {
        "snapshots": [
          {"label": "snap1", "anchor_off": int, "xp": int, "praxis": int},
          ... up to 4 entries (some may be missing)
        ],
        "inventory_sections": [
          { ... section dict from find_inventory_sections() ... },
        ],
        "items": [
          {"id": str, "name": str, "status": str,
           "count": int, "off": int, "flag": int,
           "rotation": int, "extra": bytes, "section": int},
          ...
        ],
      }
    """
    matches = list(find_all(buf, XP_PRAXIS_MAGIC))
    # form1.cs picks: snap1 = matches[0], snap2 = matches[-1], snap3 = matches[-2],
    # snap4 = matches[-3]. We pick all up to 4 but report in that order.
    snap_picks = []
    if matches:
        snap_picks.append(("snap1", matches[0]))
    if len(matches) >= 2:
        snap_picks.append(("snap2", matches[-1]))
    if len(matches) >= 3:
        snap_picks.append(("snap3", matches[-2]))
    if len(matches) >= 4:
        snap_picks.append(("snap4", matches[-3]))

    snapshots = []
    for label, off in snap_picks:
        xp_off = off - 12
        px_off = off - 8
        if xp_off < 0 or px_off + 4 > len(buf):
            continue
        snapshots.append({
            "label": label,
            "anchor_off": off,
            "xp": read_be_int32(buf, xp_off),
            "praxis": read_be_int32(buf, px_off),
        })

    # Use header-based inventory detection
    inv_sections = find_inventory_sections(buf)

    # Flatten items for backward-compatible "items" list,
    # tagging each with its section index.
    items = []
    for sec_idx, sec in enumerate(inv_sections):
        for item in sec["items"]:
            items.append({
                "id": item["id_hex"],
                "name": item["name"],
                "status": f"Pos({item['pos_x']},{item['pos_y']})",
                "count": item["count"],
                "off": item["off"],
                "flag": item["flag"],
                "rotation": item["rotation"],
                "extra": item["extra"],
                "section": sec_idx,
            })

    return {
        "snapshots": snapshots,
        "inventory_sections": inv_sections,
        "items": items,
    }

def cmd_read(args):
    """Forensic read: XP, praxis, and inventory item counts for one or more saves."""
    names = args.read_inputs or [args.input or args.broken]
    paths = [os.path.join(args.saves_dir, n) for n in names]

    results = []
    for n, p in zip(names, paths):
        try:
            buf = read_save(p)
        except (ValueError, zlib.error) as e:
            print(f"{n}: SKIP ({e})")
            results.append((n, None))
            continue
        results.append((n, read_progression(buf)))

    valid = [(n, r) for n, r in results if r is not None]
    if not valid:
        print("No readable saves.")
        return

    col_w = 18
    name_w = max(28, max(len(n) for n, _ in valid) + 4)

    print()
    print("=== XP / Praxis snapshots (BE int32 read at anchor-12 / anchor-8) ===")
    header = f"{'snapshot':<10}  {'field':<8}  " + \
        "  ".join(f"{n:<{col_w}}" for n, _ in valid)
    print(header)
    print("-" * len(header))
    for snap_label in ("snap1", "snap2", "snap3", "snap4"):
        for field in ("xp", "praxis"):
            row = [f"{snap_label:<10}", f"{field:<8}"]
            for n, r in valid:
                snap = next((s for s in r["snapshots"]
                            if s["label"] == snap_label), None)
                if snap is None:
                    cell = "—"
                else:
                    cell = f"{snap[field]:,}"
                row.append(f"{cell:<{col_w}}")
            print("  ".join(row))

    print()
    print("=== Inventory items (count, status: upg=upgraded, norm=normal, —=absent) ===")
    header = f"{'item':<{name_w}}" + \
        "  ".join(f"{n:<{col_w}}" for n, _ in valid)
    print(header)
    print("-" * len(header))
    # Sort: present-in-any-save first, then by name for readability.
    item_rows = list(zip(*[r["items"] for _, r in valid]))
    rows_with_data = [row for row in item_rows
                      if any(it["status"] != "abs" for it in row)]
    rows_absent = [row for row in item_rows
                   if all(it["status"] == "abs" for it in row)]
    for row in rows_with_data:
        name = row[0]["name"]
        cells = []
        for it in row:
            if it["status"] == "abs":
                cells.append("—")
            else:
                cells.append(f"{it['count']} ({it['status']})")
        print(f"{name:<{name_w}}" + "  ".join(f"{c:<{col_w}}" for c in cells))
    if rows_absent:
        print(f"  [{len(rows_absent)} items absent in all saves]")


def cmd_hybrid(args):
    """Original hybrid-graft experiment. Non-viable per SUMMARY §11.1 but kept
    so the failed result remains reproducible."""
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
    print(f"  broken  decompressed: {len(broken):#x} bytes ({len(broken):,})")
    print(
        f"  working decompressed: {len(working):#x} bytes ({len(working):,})")
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
    diff_summary(hybrid, broken,  "hybrid", "broken")
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

    print("Verifying roundtrip (decompress what we wrote, compare to hybrid)...")
    rt = read_save(output_path)
    if rt == hybrid:
        print("  OK: decompressed output matches hybrid byte-for-byte.")
    else:
        n = sum(1 for x, y in zip(rt, hybrid) if x != y)
        print(
            f"  FAIL: roundtrip differs in {n} bytes (CRITICAL — investigate)")
        sys.exit(1)

    print()
    print("Done. Now load the slot in-game with our hooks installed.")
    print("Watch dxhr_memfix.log for hook activity.")
    print(f"To restore {args.output}, copy {os.path.basename(bak)} back.")


def window_byte_classes(chunk: bytes) -> tuple:
    """Return (%zero, %FF, %printable) for a chunk."""
    n = len(chunk)
    if n == 0:
        return 0.0, 0.0, 0.0
    z = chunk.count(0) / n * 100.0
    f = chunk.count(0xFF) / n * 100.0
    p = sum(1 for c in chunk if 32 <= c < 127) / n * 100.0
    return z, f, p


def classify_window(z: float, f: float, p: float) -> str:
    """Classify a 2KB window. 'A' = runaway-writer signature (tight 25/25), '' = normal."""
    if (RUNAWAY_ZERO_LO <= z <= RUNAWAY_ZERO_HI
            and RUNAWAY_PRINT_LO <= p <= RUNAWAY_PRINT_HI):
        return "A"
    return ""


def scan_anomalous_regions(buf: bytes, world_start: int,
                           window: int = ANOMALY_WINDOW,
                           step: int = ANOMALY_STEP):
    """Slide a window across world state and return contiguous anomalous regions.

    Each region is a dict {start, end, length, dominant_type, windows: [(off, z, f, p, t), ...]}.
    """
    flagged = []
    end_off = len(buf) - window + 1
    for off in range(world_start, end_off, step):
        z, f, p = window_byte_classes(buf[off:off + window])
        t = classify_window(z, f, p)
        if t:
            flagged.append((off, z, f, p, t))
    if not flagged:
        return []

    regions = []
    cur = [flagged[0]]
    for entry in flagged[1:]:
        last_end = cur[-1][0] + window
        if entry[0] <= last_end:
            cur.append(entry)
        else:
            regions.append(_finalize_region(cur, window))
            cur = [entry]
    regions.append(_finalize_region(cur, window))
    return regions


def _finalize_region(windows: list, window_size: int) -> dict:
    start = windows[0][0]
    end = windows[-1][0] + window_size
    types = [w[4] for w in windows]
    dom = max(set(types), key=types.count)
    return {"start": start, "end": end, "length": end - start,
            "dominant_type": dom, "windows": windows}


def cmd_shift(args):
    """Delete the anomalous regions and shift the file to resync the serialization stream."""
    boundary = int(args.boundary, 0)
    name = args.input or args.broken
    if not name:
        raise SystemExit("--mode=shift requires --input <save>")
    
    input_path = os.path.join(args.saves_dir, name)
    output_name = args.output or f"{name}_shifted"
    output_path = os.path.join(args.saves_dir, output_name)

    print(f"Reading {input_path} for stream resync...")
    try:
        buf = bytearray(read_save(input_path))
    except Exception as e:
        raise SystemExit(f"Failed to read save: {e}")

    regions = scan_anomalous_regions(buf, boundary)
    if not regions:
        print("No anomalous regions detected. Nothing to shift.")
        return

    print(f"Detected {len(regions)} anomalous region(s):")
    total_deleted = 0
    
    # Process regions in reverse order so deleting doesn't mess up earlier offsets
    for i, r in reversed(list(enumerate(regions))):
        start = r["start"]
        end = r["end"]
        length = r["length"]
        
        # The 4 bytes right before the garbage is the corrupted 'Count' header.
        # We clamp it to 0 so LoadFromStream expects exactly 0 items.
        if start >= 4:
            count_offset = start - 4
            old_count = int.from_bytes(buf[count_offset:start], 'little')
            print(f"  [{i}] Corrupted Count Header at {hex(count_offset)}: {old_count} -> clamping to 0")
            buf[count_offset:start] = b'\x00\x00\x00\x00'

        print(f"  [{i}] Deleting {length:,} bytes from {start:#x}..{end:#x}")
        del buf[start:end]
        total_deleted += length

    print(f"Deleted {total_deleted:,} bytes of garbage. Appending zeros to maintain {DECOMP_SIZE:#x} file size...")
    buf.extend(b'\x00' * total_deleted)

    if len(buf) != DECOMP_SIZE:
        print(f"ERROR: Final size is {len(buf):#x}, expected {DECOMP_SIZE:#x}")
        return

    if args.dry_run:
        print("DRY RUN — not writing anything.")
        return

    bak = backup_file(output_path)
    if bak:
        print(f"Backed up existing {output_name} -> {os.path.basename(bak)}")
    
    print(f"Writing resynced save -> {output_path}")
    write_save(output_path, bytes(buf))
    
    if update_saveindex(args.saves_dir, output_name, output_path):
        print(f"Updated saveindex for {output_name}.")
        
    print("Done.")

def cmd_patch(args):
    """Surgically zero out the anomalous regions (runaway writer corruption)."""
    boundary = int(args.boundary, 0)
    name = args.input or args.broken
    if not name:
        raise SystemExit("--mode=patch requires --input <save>")

    input_path = os.path.join(args.saves_dir, name)
    output_name = args.output or f"{name}_patched"
    output_path = os.path.join(args.saves_dir, output_name)

    print(f"Reading {input_path} for patching...")
    try:
        buf = bytearray(read_save(input_path))
    except Exception as e:
        raise SystemExit(f"Failed to read save: {e}")

    regions = scan_anomalous_regions(buf, boundary)
    if not regions:
        print("No anomalous regions detected. Nothing to patch.")
        return

    print(f"Detected {len(regions)} anomalous region(s) to zero out:")
    total_bytes = 0
    for i, r in enumerate(regions):
        print(f"  [{i}] {r['start']:#x}..{r['end']:#x} (len={r['length']:,} bytes)")
        for off in range(r["start"], r["end"]):
            buf[off] = 0
        total_bytes += r["length"]

    print(f"Zeroed out {total_bytes:,} total bytes.")

    if args.dry_run:
        print("DRY RUN — not writing anything.")
        return

    bak = backup_file(output_path)
    if bak:
        print(f"Backed up existing {output_name} -> {os.path.basename(bak)}")

    print(f"Writing patched save -> {output_path}")
    write_save(output_path, bytes(buf))
    print("Done.")


def cmd_unpack(args):
    """Decompress a save file to raw binary for external analysis (e.g. HxD)."""
    name = args.input or args.broken
    if not name:
        raise SystemExit("--mode=unpack requires --input <save>")

    input_path = os.path.join(args.saves_dir, name)
    out_name = args.output or f"{name}.dec"
    out_path = os.path.join(args.saves_dir, out_name)

    print(f"Reading and decompressing {input_path}...")
    try:
        buf = read_save(input_path)
    except Exception as e:
        raise SystemExit(f"Failed to read save: {e}")

    with open(out_path, "wb") as f:
        f.write(buf)
    print(f"Unpacked {len(buf):,} bytes to {out_path}")


def update_saveindex(saves_dir: str, save_name: str, save_path: str) -> bool:
    """Update the saveindex file with the new file size and CRC32."""
    index_path = os.path.join(saves_dir, "saveindex")
    if not os.path.exists(index_path):
        return False

    with open(index_path, 'rb') as f:
        data = bytearray(f.read())

    name_bytes = save_name.encode('ascii') + b'\0'
    pos = data.find(name_bytes)
    if pos == -1:
        return False

    new_size = os.path.getsize(save_path)
    with open(save_path, 'rb') as f:
        file_data = f.read()
    new_crc = binascii.crc32(file_data) & 0xFFFFFFFF

    # Structure from start of name:
    # 32 bytes: null-padded string
    # 4 bytes: file size
    # 8 bytes: FILETIME
    # 4 bytes: unknown
    # 4 bytes: CRC32
    size_offset = pos + 32
    crc_offset = pos + 32 + 4 + 8 + 4

    data[size_offset:size_offset+4] = struct.pack('<I', new_size)
    data[crc_offset:crc_offset+4] = struct.pack('<I', new_crc)

    with open(index_path, 'wb') as f:
        f.write(data)
    return True


def cmd_pack(args):
    """Compress a raw binary file back into a zlib save file and update saveindex."""
    name = args.input or args.broken
    if not name:
        raise SystemExit("--mode=pack requires --input <dec_file>")

    input_path = os.path.join(args.saves_dir, name)

    # Infer the target save name (e.g. GAMER1_4.dec -> GAMER1_4)
    target_name = name.replace(".dec", "")
    out_name = args.output or target_name
    out_path = os.path.join(args.saves_dir, out_name)

    print(f"Reading raw binary {input_path}...")
    try:
        with open(input_path, "rb") as f:
            buf = f.read()
    except Exception as e:
        raise SystemExit(f"Failed to read file: {e}")

    print(f"Compressing and writing to {out_path}...")
    write_save(out_path, buf)

    # The game requires saveindex to reflect exact file size and CRC32
    if update_saveindex(args.saves_dir, out_name, out_path):
        print(f"Updated saveindex for {out_name}.")
    else:
        print(f"Warning: Could not update saveindex for {out_name}.")

    print("Done.")


def cmd_scan_anomalies(args):
    """Byte-class anomaly scanner (Phase A1, take 2)."""
    boundary = int(args.boundary, 0)

    if args.scan_all:
        files = sorted(list_save_files(args.saves_dir), key=lambda x: x[2])
        if not files:
            print(f"No save files matched in {args.saves_dir}")
            return
        print(
            f"Scanning {len(files)} saves for byte-class anomalies in {args.saves_dir}")
        print(f"World-state start : {boundary:#x}")
        print(f"Window/step       : {ANOMALY_WINDOW}/{ANOMALY_STEP} bytes")
        print(f"Signature A       : %zero in [{RUNAWAY_ZERO_LO:.0f}, {RUNAWAY_ZERO_HI:.0f}] AND "
              f"%print in [{RUNAWAY_PRINT_LO:.0f}, {RUNAWAY_PRINT_HI:.0f}]  (runaway writer)")
        print()

        rows = []
        for name, path, mtime in files:
            try:
                buf = read_save(path)
            except (ValueError, zlib.error) as e:
                rows.append((name, mtime, None, None, None, "", str(e)))
                continue
            regions = scan_anomalous_regions(buf, boundary)
            n = len(regions)
            tot = sum(r["length"] for r in regions)
            first = regions[0]["start"] if regions else None
            types = "".join(sorted({r["dominant_type"]
                            for r in regions})) or "-"
            rows.append((name, mtime, n, tot, first, types, None))

        print("=== cross-save anomaly summary (chronological by mtime) ===")
        hdr = (f"{'name':<14}  {'mtime':<19}  {'regions':>7}  "
               f"{'tot_bytes':>9}  {'first_off':>10}  types")
        print(hdr)
        print("-" * len(hdr))
        for name, mtime, n, tot, first, types, err in rows:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime))
            if err:
                short = err if len(err) < 50 else err[:47] + "..."
                print(f"{name:<14}  {ts:<19}  SKIP: {short}")
                continue
            f_str = f"{first:#010x}" if first is not None else "-"
            marker = "  <-- ANOMALY" if n > 0 else ""
            print(
                f"{name:<14}  {ts:<19}  {n:>7}  {tot:>9,}  {f_str:>10}  {types}{marker}")
        return

    name = args.input
    if not name:
        raise SystemExit(
            "--mode=scan-anomalies requires --input <save> or --scan-all")
    path = os.path.join(args.saves_dir, name)
    print(f"Scanning {path} for byte-class anomalies")
    print(f"World-state start: {boundary:#x}")
    print()
    buf = read_save(path)
    regions = scan_anomalous_regions(buf, boundary)
    print(f"{len(regions)} anomalous region(s) in world state:")
    for i, r in enumerate(regions):
        print()
        print(f"--- region #{i}: {r['start']:#x}..{r['end']:#x}  "
              f"len={r['length']:,}  dominant={r['dominant_type']} ---")
        print(f"  {'offset':>10} {'%zero':>6} {'%FF':>6} {'%print':>6} type")
        for off, z, f, p, t in r["windows"]:
            print(f"  {off:>#10x} {z:>6.1f} {f:>6.1f} {p:>6.1f}  {t}")


def cmd_scan(args):
    """Scan one or all saves for stack/heap-range uint32 hits."""
    boundary = int(args.boundary, 0)
    chunk_size = int(args.chunk_size, 0)
    top_n = args.top_n

    if args.scan_all:
        files = sorted(list_save_files(args.saves_dir), key=lambda x: x[2])
        if not files:
            print(f"No save files matched in {args.saves_dir}")
            return
        print(f"Scanning {len(files)} saves in {args.saves_dir}")
        print(f"Stack range: {STACK_RANGE[0]:#010x} - {STACK_RANGE[1]:#010x}")
        print(f"Heap range : {HEAP_RANGE[0]:#010x} - {HEAP_RANGE[1]:#010x}")
        print(f"Boundary   : {boundary:#x} (progression / world-state split)")
        print()

        rows = []
        for name, path, mtime in files:
            try:
                buf = read_save(path)
            except (ValueError, zlib.error) as e:
                rows.append((name, mtime, None, None,
                            None, None, None, str(e)))
                continue
            s = scan_buffer_summary(buf, boundary)
            stack_total = len(s["stack"])
            stack_world = sum(1 for off, _ in s["stack"] if off >= boundary)
            stack_prog = stack_total - stack_world
            heap_total = len(s["heap"])
            heap_world = sum(1 for off, _ in s["heap"] if off >= boundary)
            rows.append((name, mtime, stack_total, stack_prog, stack_world,
                         heap_total, heap_world, None))

        print("=== cross-save summary (chronological by mtime) ===")
        print(f"{'name':<14}  {'mtime':<19}  "
              f"{'STACK':>5} {'prog':>5} {'world':>6}  "
              f"{'HEAP':>4} {'world':>6}  status")
        for (name, mtime, st, sp, sw, ht, hw, err) in rows:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime))
            if err:
                short = err if len(err) < 60 else err[:57] + "..."
                print(f"{name:<14}  {ts:<19}  "
                      f"{'-':>5} {'-':>5} {'-':>6}  "
                      f"{'-':>4} {'-':>6}  SKIP: {short}")
                continue
            print(f"{name:<14}  {ts:<19}  "
                  f"{st:>5} {sp:>5} {sw:>6}  "
                  f"{ht:>4} {hw:>6}  ok")
        print()

        detailed = [(n, p, m) for (n, p, m), r in zip(files, rows)
                    if r[2] is not None and r[2] > 0]
        if detailed and not args.summary_only:
            print(
                f"=== per-save detail for {len(detailed)} saves with stack hits ===")
            for name, path, _ in detailed:
                try:
                    buf = read_save(path)
                except Exception:
                    continue
                s = scan_buffer_summary(buf, boundary)
                print()
                print_scan_detail(buf, name, s, top_n, chunk_size)
        return

    name = args.input or args.broken
    path = os.path.join(args.saves_dir, name)
    print(f"Scanning {path}")
    print(f"Stack range: {STACK_RANGE[0]:#010x} - {STACK_RANGE[1]:#010x}")
    print(f"Heap range : {HEAP_RANGE[0]:#010x} - {HEAP_RANGE[1]:#010x}")
    print(f"Boundary   : {boundary:#x}")
    print()
    buf = read_save(path)
    s = scan_buffer_summary(buf, boundary)
    print_scan_detail(buf, name, s, top_n, chunk_size)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode",
                    choices=("hybrid", "scan",
                             "scan-anomalies", "read", "patch"),
                    default="hybrid",
                    help="hybrid: graft progression+worldstate (legacy). "
                         "scan: read-only stack/heap-range uint32 hits (falsified). "
                         "scan-anomalies: detect runaway-writer byte-class signature. "
                         "read: forensic XP/praxis/inventory readout for comparison. "
                         "patch: surgically zero out anomalous regions.")
    ap.add_argument("--saves-dir", default=DEFAULT_SAVES_DIR,
                    help=f"folder containing GAMER##_4 files "
                    f"(default: {DEFAULT_SAVES_DIR})")
    ap.add_argument("--boundary", default=hex(DEFAULT_BOUNDARY),
                    help=f"progression/world-state split offset "
                    f"(default: {DEFAULT_BOUNDARY:#x})")
    ap.add_argument("--dry-run", action="store_true",
                    help="hybrid: show diffs but don't write")

    # hybrid-mode args
    ap.add_argument("--broken",  default="GAMER23_4",
                    help="hybrid: progression source (default: GAMER23_4)")
    ap.add_argument("--working", default="GAMER63_4",
                    help="hybrid: world-state source (default: GAMER63_4)")
    ap.add_argument("--output",  default="GAMER22_4",
                    help="hybrid: output slot (default: GAMER22_4)")

    # scan-mode args
    ap.add_argument("--input",
                    help="scan: single save filename (e.g. GAMER23_4)")
    ap.add_argument("--scan-all", action="store_true",
                    help="scan: walk saves-dir and report every GAME[RAQ]##_4")
    ap.add_argument("--top-n", type=int, default=DEFAULT_TOP_N,
                    help=f"scan: candidates printed per save (default: {DEFAULT_TOP_N})")
    ap.add_argument("--chunk-size", default=hex(DEFAULT_CHUNK_SIZE),
                    help=f"scan: histogram chunk size (default: {DEFAULT_CHUNK_SIZE:#x})")
    ap.add_argument("--summary-only", action="store_true",
                    help="scan --scan-all: skip per-save detail")

    # read-mode args
    ap.add_argument("--read-inputs", nargs="+",
                    help="read: list of save filenames to compare side-by-side "
                         "(e.g. --read-inputs GAMER5_4 GAMER6_4 GAMER23_4)")

    args = ap.parse_args()
    if args.mode == "hybrid":
        cmd_hybrid(args)
    elif args.mode == "scan":
        cmd_scan(args)
    elif args.mode == "scan-anomalies":
        cmd_scan_anomalies(args)
    elif args.mode == "read":
        cmd_read(args)
    elif args.mode == "patch":
        cmd_patch(args)
    elif args.mode == "unpack":
        cmd_unpack(args)
    elif args.mode == "pack":
        cmd_pack(args)
    elif args.mode == "shift":
        cmd_shift(args)


if __name__ == "__main__":
    main()
