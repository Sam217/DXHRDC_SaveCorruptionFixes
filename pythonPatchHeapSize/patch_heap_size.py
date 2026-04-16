#!/usr/bin/env python3
"""
DXHR:DC Heap Reservation Patch
================================

Patches the OSHeap::Init function in DXHRDC.exe to increase the
virtual address space reservation from 512 MB to 1.5 GB (and the
fallback from 384 MB to 1.25 GB).

This is a 4-location, 4-bytes-each patch (16 bytes total changed).

HOW THE GAME'S ALLOCATOR WORKS:
  On startup, cdc::OSHeap::Init reserves a contiguous block of
  virtual address space using VirtualAlloc(MEM_RESERVE). The game's
  dlmalloc then operates entirely within this reserved region,
  committing pages as needed via VirtualAlloc(MEM_COMMIT).

  The cdc::OSHeap::sbrk function enforces a hard limit: the heap
  can NEVER grow beyond the initial reservation. If it tries,
  sbrk returns -1, dlmalloc fails, and the game crashes with
  "ERROR: Out of memory".

  The reservation is currently 512 MB (0x20000000), or 384 MB
  (0x18000000) as a fallback. On a 64-bit Windows system with the
  EXE being LARGEADDRESSAWARE, there's ~3.5 GB of address space
  available — the game just doesn't use it.

WHY EACH CONSTANT APPEARS TWICE:
  PUSH 0x20000000    → tells VirtualAlloc how much to reserve
  MOV  [ESI+0x438], 0x20000000  → stores the limit for sbrk to enforce

  Both must be patched. Otherwise:
  - PUSH only: OS reserves more, but sbrk still refuses at 512 MB
  - MOV only:  sbrk allows growth beyond reservation → crash

PATCH LOCATIONS (RVAs from Ghidra, image base = 0):
  1. RVA 0x0020290F: PUSH immediate  (0x20000000 → 0x60000000)
  2. RVA 0x00202921: MOV  immediate  (0x20000000 → 0x60000000)
  3. RVA 0x0020293F: PUSH immediate  (0x18000000 → 0x50000000)
  4. RVA 0x0020294A: MOV  immediate  (0x18000000 → 0x50000000)

Usage:
    python patch_heap_size.py DXHRDC.exe
    python patch_heap_size.py DXHRDC.exe --output DXHRDC_patched.exe
    python patch_heap_size.py DXHRDC.exe --size 1536   (size in MB, default 1536)
"""

import struct
import sys
import shutil
import os
import argparse

# ─── Patch signatures ─────────────────────────────────────────────
# We search for the BYTE PATTERNS rather than relying on fixed file
# offsets, which makes this robust across different builds/packers.

# Pattern 1: Primary reservation (512 MB)
# PUSH 1 / PUSH 0x2000 / PUSH 0x20000000 / PUSH 0
#   6A 01 68 00 20 00 00 68 [00 00 00 20] 6A 00
#                            ^^^^^^^^^^^^ this is what we patch
PATTERN_PRIMARY_PUSH = bytes([
    0x6A, 0x01,                         # PUSH 1
    0x68, 0x00, 0x20, 0x00, 0x00,       # PUSH 0x2000
    0x68, 0x00, 0x00, 0x00, 0x20,       # PUSH 0x20000000  ← patch bytes 8..11
    0x6A, 0x00,                         # PUSH 0
])
PRIMARY_PUSH_OFFSET = 8  # offset within pattern to the 4-byte immediate

# Pattern 2: Primary MOV (store reservedSize)
# MOV dword ptr [ESI + 0x438], 0x20000000
#   C7 86 38 04 00 00 [00 00 00 20]
#                      ^^^^^^^^^^^^ patch these
PATTERN_PRIMARY_MOV = bytes([
    0xC7, 0x86, 0x38, 0x04, 0x00, 0x00,  # MOV [ESI+0x438],
    0x00, 0x00, 0x00, 0x20,               # 0x20000000  ← patch bytes 6..9
])
PRIMARY_MOV_OFFSET = 6

# Pattern 3: Fallback PUSH (384 MB)
# PUSH 0x18000000
#   68 [00 00 00 18]
# But we need context to avoid false matches. The full sequence is:
# PUSH 1 / PUSH 0x2000 / PUSH 0x18000000 / PUSH EAX
#   6A 01 68 00 20 00 00 68 [00 00 00 18] 50
PATTERN_FALLBACK_PUSH = bytes([
    0x6A, 0x01,                         # PUSH 1
    0x68, 0x00, 0x20, 0x00, 0x00,       # PUSH 0x2000
    0x68, 0x00, 0x00, 0x00, 0x18,       # PUSH 0x18000000  ← patch bytes 8..11
    0x50,                               # PUSH EAX
])
FALLBACK_PUSH_OFFSET = 8

# Pattern 4: Fallback MOV (store reservedSize)
# MOV dword ptr [ESI + 0x438], 0x18000000
#   C7 86 38 04 00 00 [00 00 00 18]
PATTERN_FALLBACK_MOV = bytes([
    0xC7, 0x86, 0x38, 0x04, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x18,
])
FALLBACK_MOV_OFFSET = 6


def find_pattern(data, pattern):
    """Find all occurrences of pattern in data. Returns list of offsets."""
    results = []
    start = 0
    while True:
        idx = data.find(pattern, start)
        if idx == -1:
            break
        results.append(idx)
        start = idx + 1
    return results


def patch_bytes(data, offset, old_val, new_val):
    """Patch 4 bytes (little-endian uint32) at offset."""
    old_bytes = struct.pack('<I', old_val)
    new_bytes = struct.pack('<I', new_val)

    actual = data[offset:offset+4]
    if actual != old_bytes:
        print(f"  WARNING: Expected {old_bytes.hex()} at 0x{offset:X}, "
              f"found {actual.hex()}")
        return data, False

    data = bytearray(data)
    data[offset:offset+4] = new_bytes
    print(f"  Patched 0x{offset:X}: {old_bytes.hex()} → {new_bytes.hex()}")
    return bytes(data), True


def apply_patch(input_path, output_path, new_primary_mb, new_fallback_mb):
    new_primary  = new_primary_mb  * 1024 * 1024
    new_fallback = new_fallback_mb * 1024 * 1024

    print(f"Reading: {input_path}")
    with open(input_path, 'rb') as f:
        data = f.read()
    print(f"  File size: {len(data):,} bytes")

    # ── Check if already patched ──
    if data.find(struct.pack('<I', new_primary)) != -1:
        # Check if our specific pattern already has the new value
        test_pattern = bytes([0x68]) + struct.pack('<I', new_primary)
        if data.find(test_pattern) != -1:
            print(f"\n  NOTE: Value 0x{new_primary:X} ({new_primary_mb} MB) "
                  f"already found in file.")
            print(f"  The file may already be patched. Continuing anyway...\n")

    # ── Find patterns ──
    patches = [
        ("Primary PUSH (VirtualAlloc size)",
         PATTERN_PRIMARY_PUSH, PRIMARY_PUSH_OFFSET,
         0x20000000, new_primary),

        ("Primary MOV  (sbrk limit)",
         PATTERN_PRIMARY_MOV, PRIMARY_MOV_OFFSET,
         0x20000000, new_primary),

        ("Fallback PUSH (VirtualAlloc size)",
         PATTERN_FALLBACK_PUSH, FALLBACK_PUSH_OFFSET,
         0x18000000, new_fallback),

        ("Fallback MOV  (sbrk limit)",
         PATTERN_FALLBACK_MOV, FALLBACK_MOV_OFFSET,
         0x18000000, new_fallback),
    ]

    success_count = 0
    for name, pattern, imm_offset, old_val, new_val in patches:
        print(f"\n[{name}]")
        print(f"  Searching for pattern: {pattern.hex()}")

        locations = find_pattern(data, pattern)
        if len(locations) == 0:
            print(f"  ERROR: Pattern not found!")
            print(f"  This binary may be a different version or already patched.")
            continue
        elif len(locations) > 1:
            print(f"  WARNING: Pattern found {len(locations)} times! "
                  f"Expected exactly 1.")
            print(f"  Locations: {[hex(x) for x in locations]}")
            print(f"  Using first match.")

        file_offset = locations[0] + imm_offset
        print(f"  Pattern found at file offset: 0x{locations[0]:X}")
        print(f"  Immediate value at file offset: 0x{file_offset:X}")
        print(f"  Changing: 0x{old_val:X} ({old_val // (1024*1024)} MB) "
              f"→ 0x{new_val:X} ({new_val // (1024*1024)} MB)")

        data, ok = patch_bytes(data, file_offset, old_val, new_val)
        if ok:
            success_count += 1

    print(f"\n{'='*60}")
    print(f"Patches applied: {success_count}/4")

    if success_count < 4:
        print(f"\nWARNING: Not all patches applied! The fix may not work.")
        print(f"Check the output above for details.")
    else:
        print(f"\nAll patches applied successfully!")

    # ── Backup & write ──
    if output_path == input_path:
        backup = input_path + ".bak"
        if not os.path.exists(backup):
            shutil.copy2(input_path, backup)
            print(f"Backup created: {backup}")
        else:
            print(f"Backup already exists: {backup}")

    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Output written: {output_path}")

    print(f"""
Summary:
  Heap reservation: 512 MB → {new_primary_mb} MB
  Heap fallback:    384 MB → {new_fallback_mb} MB

  The game's dlmalloc pool can now grow to {new_primary_mb} MB,
  which should easily accommodate the 256 MB "Misc" allocation
  that was causing the OOM crash on save load.
""")


def main():
    parser = argparse.ArgumentParser(
        description='DXHR:DC Heap Reservation Patch — '
                    'increases game heap from 512 MB to 1.5 GB')
    parser.add_argument('input', help='Path to DXHRDC.exe')
    parser.add_argument('--output', '-o', default=None,
                        help='Output path (default: patch in-place with .bak)')
    parser.add_argument('--size', type=int, default=1536,
                        help='New primary heap size in MB (default: 1536 = 1.5 GB)')
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"ERROR: File not found: {args.input}")
        sys.exit(1)

    output = args.output or args.input
    primary_mb = args.size
    # Fallback is primary minus 256 MB (mirroring original 512-384=128 gap,
    # but scaled up). Minimum 512 MB.
    fallback_mb = max(512, primary_mb - 256)

    # Sanity checks
    if primary_mb < 512:
        print("ERROR: --size must be at least 512 MB")
        sys.exit(1)
    if primary_mb > 3072:
        print("WARNING: Sizes above 3072 MB (3 GB) may cause issues "
              "with 32-bit address space.")
        print("Proceeding anyway...")

    # Ensure values are aligned to 16 MB (0x1000000) for clean reservation
    primary_bytes = primary_mb * 1024 * 1024
    if primary_bytes % (16 * 1024 * 1024) != 0:
        aligned = ((primary_bytes + 0xFFFFFF) & ~0xFFFFFF)
        primary_mb = aligned // (1024 * 1024)
        print(f"NOTE: Aligned size to {primary_mb} MB "
              f"(0x{aligned:X}) for 16 MB boundary")
        fallback_mb = max(512, primary_mb - 256)

    apply_patch(args.input, output, primary_mb, fallback_mb)


if __name__ == '__main__':
    main()
