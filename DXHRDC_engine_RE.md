# DXHRDC Engine — Reverse Engineering Knowledge Base

**Companion to** [SUMMARY.md](SUMMARY.md) (chronological narrative of the
fix effort) **and** [CLAUDE.md](.claude/worktrees/bold-shamir-df882c/CLAUDE.md)
(quick-start guide). This document is a **reference** — function map,
relationships, semantics. The Ghidra project has the renames and
comments; this file is the human-readable companion that survives
across Ghidra sessions and chat resets.

## Conventions

- All addresses are **RVAs** (relative to image base; `0x00DE0000` was
  observed at runtime but Ghidra holds DXHRDC.exe at base 0). To
  convert a runtime address: `RVA = runtime_addr - 0x00DE0000`.
- Calling conventions: 32-bit MSVC. `__thiscall` = `this` in `ECX`,
  args on stack right-to-left, callee-cleans (`RET imm16`). Captured
  from C as `__fastcall(this, edx_unused, ...)`.
- Hook status flags:
  - 🪝 = function is hooked by `version_proxy.c`
  - ⚠️ = function has a known engine bug
  - 🩹 = bug is mitigated by our hook
  - ❌ = bug is not yet mitigated
- "Unsafe" patterns we keep finding:
  - **NULL guard then deref outside** the guard
  - **Bounds check that calls a handler but doesn't `return`**
  - **Uninitialized stack variable used as loop counter** when stream
    is exhausted

---

## Subsystem 1: Allocator

The game's heap is a custom dlmalloc operating within a fixed
`VirtualAlloc(MEM_RESERVE)` region. See SUMMARY §3 for the 512 MB
ceiling story.

### Allocator class hierarchy
```
cdc::OSHeap                      VA reservation, sbrk
  └─ cdc::dlmalloc                 best-fit + bins
       └─ cdc::MemHeapAllocator      bin-allocator wrapper, vtable dispatch
            └─ cdc::ThreadSafeMemHeapAllocator   crit-section wrap
                 └─ cdc::GameHeapAllocator         game-init wrapper
```

### Functions

| RVA | Symbol | Notes |
|---|---|---|
| `0x1FB660` | `cdc::GetHeapCategoryName(int id)` | 🪝 Hook 9. Indexes table at `DAT_015ED7B0+0xD4+id*4`. Returns `&DAT_006902B8` ("???") on miss. |
| `0x1FB890` | `AllocatorManager::Init` | Constructs all heap instances. |
| `0x1FBC60` | `GamePrintError(fmt, ...)` | 🪝 Hook 1. **Engine's assert()** — calls `__vsnprintf` then `HideGameWindowAndShowError` then `int 3`. **Callers don't NULL-check after, because they assume it never returns.** Our hook returns when `g_suppressOOM` set. Suppressing other paths breaks implicit-assert callers (see SUMMARY §9.5). |
| `0x1FCC00` | `cdc::dlfree` | Block coalescing. |
| `0x1FCE00` | `dlmalloc_GrowHeap` | Calls sbrk. |
| `0x1FCF90` | `cdc::dlmalloc` | Bins-and-tree best-fit. |
| `0x1FD930` | `dlmemalign` | Aligned alloc core. |
| `0x1FDCC0` | `cdc::MemHeapAllocator::Allocate(size, cat)` | 🪝 Hook 2. `__thiscall`. Calls `vtable[+0x5c]` (= `PrimaryAlloc`). On NULL: tries fallback alloc; otherwise calls `GamePrintError` with "ERROR: Out of memory, %s requested..." format `0x6A1A70`. |
| `0x1FDE30` | `cdc::MemHeapAllocator::AllocateAligned(align, size, cat)` | 🪝 Hook 3. Same pattern. |
| `0x1FE010` | `cdc::MemHeapAllocator::Free(ptr)` | 🪝 Hook 4. Required because passing a `VirtualAlloc`'d fallback ptr to dlmalloc corrupts the heap. |
| `0x1FE310` | `cdc::ThreadSafeAlloc` | Lock + `Allocate` + unlock. |
| `0x1FE350` | `cdc::ThreadSafeAllocAligned` | Same for aligned. |
| `0x1FE460` | `cdc::GameHeapAllocator::Init` | Game-specific init. |
| `0x1FE4E0` | `cdc::MemHeapAllocator::PrimaryAlloc` | **Was misnamed "Path B" / DirectMalloc** in old SUMMARY. Only one xref — vtable slot `0x006A1C50+0x5C`. **Always reached via vtable from `Allocate`** (not a separate path). Hook 10 removed for this reason. |
| `0x1FE540` | Lock + Allocate wrapper | Another vtable-backed alloc entry. |
| `0x2028B0` | `cdc::OSHeap::Init` | ⚠️ Has the **hardcoded 512 MB / 384 MB reservation**. `pythonPatchHeapSize/patch_heap_size.py` patches the constants. |
| `0x2029D0` | `cdc::OSHeap::sbrk` | Bounded growth within reservation. |
| `0x202A42` | (sbrk + 0x72, instr inside sbrk) | Frame previously masked by removed Hook 10. |

### MemHeapAllocator instance layout
```
+0x00  vtable
+0x04  dlmalloc bins (~0x400 bytes)
+0x14  heap base
+0x1C  alloc count
+0x20  total allocated bytes
+0x24  internal dlmalloc state
+0x30  recursion guard (1 byte)
+0x31  ownership flag (1 byte)
+0x34  fallback allocator pointer
+0x38  lock object pointer
```

### Vtable layout (`DAT_006A1C50`)
```
+0x08  GrowHeap
+0x18  OwnsPointer
+0x34  FallbackAlloc
+0x38  FallbackFree
+0x4C  GetTotalCapacity
+0x58  GetUsedBytes
+0x5C  PrimaryAlloc            <- FUN_001FE4E0
+0x60  PrimaryAllocAligned
```

---

## Subsystem 2: Save system entry / dispatch

User clicks "Load Save" → string-dispatched command handler routes to
the right operation. None of these functions are hooked.

| RVA | Function | Notes |
|---|---|---|
| `0x408BB0` | Save-system command handler | String-switch over verbs: `RequestSlotInfo`, `RequestDeviceInfo`, `GetCurrentDLCPackId`, `IsGameInProgress`, `SaveNewGame`, `OverwriteExistingGame`, `LoadExistingSavedGame`, `LoadSavedGameThumbnail`, `DeleteSavedGame`. Strings inline-compared via `__strnicmp`-equivalent loops. |
| `0x33CA30` | Validate slot metadata | Returns 1 → "Damaged Save Game" dialog. Just metadata check, NOT file parsing. |
| `0x1AF980` | Read slot-info flag | Helper for the validator. |
| `0x33CDD0` | Save-load state machine | Allocates the **`0x23A000`-byte** save buffer (matches PC zlib decompressed size). Calls `FUN_001AC850` / `FUN_002032F0` / `FUN_001B0450`. |
| `0x1AC850` | Allocate save buffer | Takes size as arg; called with `0x23A000`. |
| `0x002032F0` | Save I/O helper | Composition. |
| `0x1B0450` | Save I/O helper | Composition. |

### "Damaged save" dialog string IDs (resources)
- `SaveSystem_DamagedSaveGame` — main "this save is broken" message
- `SaveSystem_InvalidSaveGameTitle` — dialog title
- `SaveSystem_LoadError` / `SaveSystem_SaveError` — generic
- `SaveSystem_LoadingInProgress` / `SaveSystem_SavingInProgress`
- `SaveSystem_SigninChanged` — Xbox Live carryover
- `SaveSystem_OverwriteSaveGame{Title}` — overwrite confirmation
- All in `.rdata` around `0x6BE3F4..0x6BE510`.

---

## Subsystem 3: InstanceTable (the actual save serialization)

Saves a list of "instances" (game objects) by ID. Inverse functions
form a Save/Load pair via the same vtable.

### Vtable (`DAT_006955C4`)
```
+0x00  SaveToStream     <- FUN_000ECC00
+0x04  LoadFromStream   <- FUN_000ECEB0
```
Class is named `cdc::DeferredLightComponent` in the constructor at
`0x000ECF60` and `0x000ECFB0`, but the methods themselves are named
`cdc::InstanceTable::*` — likely Ghidra naming inconsistency. Treat
the class as `InstanceTable` for our purposes.

### Functions

| RVA | Symbol | Notes |
|---|---|---|
| `0x0ECC00` | `cdc::InstanceTable::SaveToStream(stream)` | **Structurally sane** — reads from `this->[+0x4]` (flag), `this->[+0x14]` (count), `this->[+0x1C+i*8]` (entries) and writes them. Two-pass count-then-write pattern (`stream[3] != 0` = counting mode). **But `this->[+0x14]` may be garbage in memory at save time → corruption propagates.** |
| `0x0ECC80` | `cdc::InstanceTable::RestoreInstance(desc)` | 🪝 Hook 15 SEH. Reads MANY fields off `desc + 0x11C..+0x12C+`. If `desc` is corrupt, reads fault. Function already has multiple `return 0` early-exits; SEH-catch + return 0 has same semantic ("skip this instance"). Caller's loop checks return value. |
| `0x0ECEB0` | `cdc::InstanceTable::LoadFromStream(stream)` | 🪝 Hook 5 (with stream-exhaustion fix `fcb20dd`). ⚠️ Initializes `puVar1 = param_1` (a stack pointer = ~`0x02BDXXXX`) **BEFORE** conditionally reading the count from stream. When stream exhausted, count read is skipped → loop runs ~45M times. Our hook: detects `pos+5 > total` → early return without calling original. Also caps count to `MAX_INSTANCES = 50000`. |

### Stream object layout (the `stream` arg to all of these)
```
[0]  consumed   (uint, current read position)
[1]  total      (uint, buffer size)
[2]  read_ptr   (BYTE*, base + consumed)
[3]  flags      (low bit = counting-mode: don't actually read/write data, just advance)
```

### LoadFromStream's loop (the corruption amplifier)

```c
puVar1 = param_1;                        // ★ initial value: stack address ~45M
if (*param_1 + 1 <= param_1[1]) { read flag; advance 1; }
if (*param_1 + 4 <= param_1[1]) {
    puVar1 = *(uint **)param_1[2];        // overwrite with real count
    advance 4;
}
for (; puVar1 != NULL; puVar1 = puVar1 - 1) {  // 45M+ iterations on exhausted stream
    if (*param_1 + 4 <= param_1[1]) { read idx; advance 4; }
    iVar2 = RestoreInstance(idx * 0x130 + this->table_at_0x10);
    if (iVar2 != 0) DynArray_PushBack_8bytes(...);
}
```

Hook 5 detects the no-data case at function entry and bails entirely.

---

## Subsystem 4: Resource lookup chain

Used during instance restoration: instance descriptor has a "DRM
resource id" → look up filename → load `.drm` file → instance gets a
pointer to the loaded resource.

### Functions

| RVA | Symbol | Notes |
|---|---|---|
| `0x0A4240` | `BuildDrmFilename(buf, name)` | 🪝 Hook 11. One-line wrapper: `_sprintf(buf, "%s%s.drm", &DAT_00A5B530, name)`. Hook validates `name` ptr (LAA-aware bounds + IsBadReadPtr); writes empty string on rejection. |
| `0x0EDCC0` | `LoadDrmResourceById(idx, p2)` | 🪝 Hook 12. ⚠️ Buggy bounds check (calls handler but doesn't abort). On miss, allocates cache slot via `FUN_000ED610`, computes `filename_ptr = table[idx*8]`, calls `BuildDrmFilename`, then `FUN_001A7590` to load. Hook 12 validates idx range AND reads filename_ptr value upfront — early-returns on either bad case. |
| `0x0EDE40` | (thin wrapper) | `LoadDrmResourceById(idx, 3)`. Used by save-loading paths. |
| `0x0EDE50` | (thin wrapper) | Similar. |
| `0x0ED610` | Allocate cache slot | Inputs: idx, flag. |
| `0x0ED680` | (referenced from RestoreInstance) | Lookup-related. |
| `0x0ED8F0` | Reload table from `objectlist.txt` | Parses `objectlist.txt` (`%s\objectlist.txt`), allocates new table, populates entries. **Counter-intuitive**: `[table+0]` stores **max_id** (1-based), NOT entry count. So `idx ∈ [1, max_id]` is valid; idx=0 reads max_id-as-pointer = the famous `0x1005` for level "Hei Zhen Zhu" (max_id=4101=0x1005). |
| `0x0ED7A0` | (callback referenced from `LoadDrmResourceById`) | Used by FUN_001A7590. |
| `0x1A4C80` | Object lookup by id (small ID range) | 🪝 Hook 13. **100+ legitimate callers**, returns `entry+0x10` on hit, **0 on miss**. Constraint: `id < 0x18000 && DAT_015806E8[id] != 0 && entry->flag == 0`. Hook 13 substitutes a 16-uint zero stub when caller's RA is inside the deserializer family `[0x25B000, 0x260000)` — leaves all other callers alone. |
| `0x1A6AA0` | Loader callback | Argument to `FUN_001A7590`. |
| `0x1A75E0` | `DRMLoader::ProcessData` | Level-section state machine. |
| `0x1A7590` | Resource loader (file open + load) | Called by `LoadDrmResourceById`. Contains `FUN_0009E330`/`FUN_0009E490` chain that asserts via `GamePrintError` on missing file. |

### DRM table layout (target of `LoadDrmResourceById`)

Located via `DAT_00A9A43C`:
```
table_ptr_ptr = (int**)(DAT_00A9A43C + 0x18);  // pointer to pointer
table_base    = *table_ptr_ptr;
table_base[0] = max_id (1-based)
table_base[1] = data buffer pointer
table_base[2 + (idx-1)*2 + 0] = entry filename ptr   // = [base + idx*8]
table_base[2 + (idx-1)*2 + 1] = entry id             // = [base + idx*8 + 4]
```

### File-open assertion path

| RVA | Function | Notes |
|---|---|---|
| `0x09E330` | Bigfile/local lookup by filename | Returns NULL on miss. |
| `0x09E490` | "Can't open file" path | ⚠️ Calls `FUN_0009E330(filename)`. If returns NULL, calls `GamePrintError("Can't open file %s\n", filename)` (the engine's assert). **Code below the assert is NOT NULL-checked.** When we erroneously suppressed the assert (commit `71a1e8e`, reverted in `b846d9d`), this caused `puVar3[1]` deref of NULL+4 = crash at RVA `0x9E4E9`. |

---

## Subsystem 5: HUD / DynArray helpers

| RVA | Symbol | Notes |
|---|---|---|
| `0x14EC40` | `cdc::DynArray4_PushBack(arr)` | 🪝 Hook 7 (cap 100K). Generic push for 4-byte-element dynamic arrays. |
| `0x1385C0` | `ArrayCopyElements(dest, src, n)` | Memory copy used during DynArray reallocation. Crash here was the original v1.4-v1.6 symptom (overflow → -2GB → ArrayCopyElements(NULL, ...)). |
| `0x215FC0` | (init helper used by Hook 8's reimpl) | Called as part of `Hud::LoadActiveGroups` setup. |
| `0x2B0DD0` | `cdc::DynArray_PushBack_8bytes(arr)` | 🪝 Hook 6 (cap 100K). Generic push for 8-byte-element dynamic arrays. |
| `0x41DE80` | `Hud::PushActiveGroup(grp_addr, ...)` | Called from inside Hook 8's reimpl. |
| `0x41E080` | `Hud::LoadActiveGroups(stream)` | 🪝 Hook 8 (full reimpl). ⚠️ Original has `while(true)` loop that breaks only on a 0 terminator. On a truncated stream the last non-zero value persists in the count register and the exit condition never fires → infinite loop. Hook 8 reimplements with a stream-exhaustion check and a 1000-iteration cap. |

---

## Subsystem 6: Instance restoration tree (the typical save-load crash chain)

This is the chain the corrupted save data flows through. Source is the
level loader; sink is the deserializer family. Each level adds context.

```
Game thread
└── cdc::ProcessFrame                                     (not investigated)
    └── FUN_0022FF60   level/scene loader                 (frame top)
        └── FUN_00209E80   "instance restoration outer"   (FUN_00209a30)
            └── FUN_002092DC   "instance + script setup"  (FUN_00209290)
                └── FUN_002080A0   FUN_00207ef0 body      (instance creation; resolves desc)
                    └── (vtable+0x20 or vtable+0x34) on this->[+0x58]
                        ├── FallbackAlloc path            (vtable+0x34)
                        └── alt path with extra arg       (vtable+0x20)
                            └── ... FUN_00388e20 saveload bridge
                                └── FUN_0025E090   save deserializer  ⚠️
                                    ├── (in loop, ~N times where N from stream)
                                    │   └── FUN_001A4C80(id)    (Hook 13 catches misses)
                                    └── FUN_0025CB50            ⚠️ piVar3[6] deref of NULL
                                        └── FUN_001A4C80(id)    (Hook 13 catches misses)
```

Other peer functions in the deserializer family — likely all share
the same NULL-guard bug pattern (only checked some explicitly):

| RVA | Notes |
|---|---|
| `0x25BB50` | Calls `FUN_001A4C80`. |
| `0x25C580` | Calls `FUN_001A4C80` (×2). |
| `0x25CB50` | ⚠️ Confirmed bug: `if (piVar3[6] != 0)` deref without NULL guard. |
| `0x25DCC0` | Calls `FUN_001A4C80`. |
| `0x25DE90` | Calls `FUN_001A4C80`. |
| `0x25DF50` | Calls `FUN_001A4C80` (×2). |
| `0x25E010` | Calls `FUN_001A4C80`. |
| `0x25E090` | ⚠️ Confirmed bug: NULL guard then deref outside. Source of `LoadDrmResourceById` calls (via `BuildDrmFilename` chain). |
| `0x25E390` | Calls `FUN_001A4C80`. |

Hook 13 covers all of these via the wide RA range `[0x25B000, 0x260000)`.

---

## Subsystem 7: FUN_00065180 — vtable NULL deref

Distinct from the deserializer family but same bug class. Takes a
stream, reads an index, looks up an object pointer in a table, **tail
calls** a virtual method on it. NO NULL guard.

| RVA | Symbol | Notes |
|---|---|---|
| `0x00065180` | (no name) | 🪝 Hook 14 SEH. The buggy function. |
| `0x00065020` | (state init) | Called at start of `FUN_00065180`. Touches several fields, registers `atexit(FUN_00671D50)`. Important to call before doing anything else. |

### The bug at the bottom of FUN_00065180 (RVA 0x651DC)
```
MOV ECX, [EDX + EBX*4]    ; ECX = piVar1 = table[idx*4]
MOV [ESI+0x28], ECX        ; this->field_0x28  = piVar1   (write happens before crash)
MOV [ESI+0x15c], ECX       ; this->field_0x15c = piVar1
MOV EDX, [ECX]             ; ★ EDX = *piVar1 → CRASH at NULL+0
... tail call vtable[+0x58](piVar1, stream)
```

After SEH catch, `this->field_0x28` and `+0x15c` are NULL — beneficial
for downstream NULL-check paths.

---

## Subsystem 8: __output_l / printf chain (the original 0x1005 crash site)

DXHRDC is statically linked against VS 2008 CRT. Several printf
variants share `__output_l`.

| RVA | Symbol | Notes |
|---|---|---|
| `0x634D08` | `_sprintf` | Calls `__output_l`. |
| `0x634D5D` | (call site inside `_sprintf` to `__output_l`) | |
| `0x6360D6` | `_fprintf` | Calls `__output_l`. |
| `0x635475` | `__vsprintf_l` | Calls `__output_l`. |
| `0x6368C4` | `_printf` | Calls `__output_l`. |
| `0x638DEC` | `__snprintf` | Calls `__output_l`. |
| `0x63A1EE` | `__vsnprintf_l` | Calls `__output_l`. |
| `0x64164F` | `__output_l(File, Format, Locale, ArgList)` | The CRT formatter. |
| `0x641FDE` | (instr inside `__output_l`) | ⚠️ The `%s` walker: `MOV byte ptr [EAX], 0` faults when the va_list provides EAX = 0x1005 (= max_id of level reinterpreted as ptr). |
| `0x64AC33` | `__woutput_l` | Wide-char variant. |

### How it gets triggered (without our fixes)
```
LoadDrmResourceById(idx=0)
  └── tableBase[0] read = max_id = 4101 = 0x1005    (wrong! that's a count, not a ptr)
      └── BuildDrmFilename(buf, 0x1005)
          └── _sprintf(buf, "%s%s.drm", prefix, 0x1005)
              └── __output_l → walks (char *)0x1005 → fault
```

Hook 11 catches the bad pointer at `BuildDrmFilename` level; Hook 12
catches the idx=0 case earlier at `LoadDrmResourceById` level.

---

## Globals reference

| RVA | Symbol | Description |
|---|---|---|
| `0x015ED7B0` | (global allocator manager) | `+0x48` resource alloc · `+0x4C` main heap allocator instance · `+0xD4` category names table |
| `0x00A9A43C` | (DRM lookup global) | `*(int**)+0x18` = DRM-resource-table base; `[+0x00]` = max_id, `[+0x04]` = data buffer, entries at `[+idx*8]` |
| `0x015806E8` | (small-id object table) | Used by `FUN_001A4C80`. Indexed by id (id < 0x18000). |
| `0x006A1C50` | `cdc::MemHeapAllocator` vtable | `+0x5C` PrimaryAlloc · `+0x60` PrimaryAllocAligned · `+0x34` FallbackAlloc · `+0x4C` GetTotalCapacity · `+0x58` GetUsedBytes |
| `0x006955C4` | `cdc::InstanceTable`/`DeferredLightComponent` vtable | `+0x00` SaveToStream · `+0x04` LoadFromStream |
| `0x00A1F148` | (security cookie) | `__security_cookie`, used by all `/GS` functions. |
| `0x00A5B530` | (DRM filename prefix) | First arg to `_sprintf` in `BuildDrmFilename`. |
| `0x006A1A70` | "ERROR: Out of memory, %s requested..." format | OOM error string used by `MemHeapAllocator::Allocate`. |
| `0x006902B8` | "???" or similar | Default category name returned by `GetHeapCategoryName` on miss. |
| `0x00689688` | (float constant) | Used in `Allocate`'s OOM size formatting (probably `2^32` for unsigned-to-double). |

---

## Save format reference (PC, DXHRDC)

See SUMMARY §10 for full discussion. Quick form:

| Property | Value |
|---|---|
| File location | `<Steam>/userdata/<userid>/238010/remote/GAMER##_4` |
| Compression | zlib default (78 9C magic) |
| Decompressed size | exactly **`0x23A000` = 2,334,720 bytes** |
| Encryption | none |
| Checksum/signature | none |
| Header `[0..4)` | uint32 LE = "data length" (varies per save; perhaps where engine zero-pads) |
| Inventory record | 9 bytes: `[ID 3B BE | 00 00 | DATA 2B | 00 00]` |
| Item IDs (3B BE) | match Xbox 360 save editor (e.g., painkillers `0x001F51`) |
| Snapshots per save | ~6 redundant copies of inventory/aug data |

### File regions (empirical from GAMER63 vs GAMER23 diff)

| Range | Description |
|---|---|
| `0x000000–0x006000` | "Player progression header proper" — playtime, save metadata, story flags |
| `0x006000–0x0F0000` | Mostly stable in same chapter (~99.98% identity GAMER23 vs GAMER63) |
| `0x0F0000–0x23A000` | "Per-session world state" — instances, NPC positions, ragdolls. **Heavy diff between saves**, **THIS is where corruption lives** |

⚠️ **Crucially**: header and world state are NOT independent. They
cross-reference each other through at least one shared index/table-
lookup space (proven by the failed hybrid-graft experiment in
SUMMARY §11.1). A repair tool must keep one save **consistent**
end-to-end, not graft across saves.

---

## Crash signatures we've seen and their causes

Catalog of crash addresses we've observed in the field, with their
root causes (so a future session can match a new crash to a known
class quickly).

| Crash RVA | Op | Cause | Mitigation |
|---|---|---|---|
| `0x641FDE` | READ at `0x1005` | `_sprintf("%s%s.drm", ..., max_id)` because LoadDrmResourceById was called with idx=0 → tableBase[0]=max_id used as filename ptr | Hook 11 + Hook 12 |
| `0x25E1EA` | READ at `0x4` | `puVar8[1]` deref outside NULL guard in `FUN_0025E090` | Hook 13 |
| `0x25CB67` | READ at `0x18` | `piVar3[6]` deref without NULL guard in `FUN_0025CB50` | Hook 13 |
| `0x651DC` | READ at `0x0` | `*piVar1` (vtable load) without NULL guard in `FUN_00065180` | Hook 14 SEH |
| `0xECCFD` | READ at `0x7F0XXXXX` | `MOVZX EAX, [EBX + 0x11C]` in `RestoreInstance` with corrupt descriptor pointer | Hook 15 SEH |
| `0x9E4E9` | READ at `0x4` | `puVar3[1]` deref after suppressed `GamePrintError("Can't open file")` | Reverted suppression — keep the assert |
| `0x20845E` | READ at `0xD8` | Hybrid-graft inconsistency — index 0x77 lookup into NULL table when progression and world state disagree | **DON'T do hybrid graft** — keep saves consistent |

When a new crash signature shows up, the playbook is:
1. Decompile the function at the crash RVA.
2. Look at the instruction at the exact crash offset — what's it
   dereferencing?
3. Check whether the function has the typical "guard-then-deref"
   pattern. If yes → SEH wrap or input validation.
4. If the function is in the deserializer family `[0x25B000, 0x260000)`
   and calls `FUN_001A4C80`, Hook 13 should already cover it — verify.
5. If it's deeper in the chain (post-deserializer), it might be one
   of the engine's many "trust the loaded data" assumptions and need
   its own SEH wrap.

---

## Open questions / things not investigated

- Save format **chunk structure** — we know it's a `0x23A000` flat
  buffer with mixed regions, but the engine probably parses it as a
  series of (tag, size, data) chunks. Identifying chunk boundaries
  would let a repair tool target specific sections (HUD, inventory,
  instances) rather than blunt-zero everything in stack-address range.
- The **save-index file** — separate from the save-content files,
  determines which slots are valid. Location and format unknown to
  us. There's a small GitHub project addressing it (TODO: link).
- Why the **101 KB chunk** (`102400 = 0x19000`) appears as the "total"
  in the exhausted `LoadActiveGroups` stream — likely the section size
  reserved for HUD active groups in the save format. Could confirm by
  searching for this length value across saves.
- The **"6 snapshots in one save"** observation — we see ~6 redundant
  copies of inventory blocks per save. Maybe quicksave + autosave +
  recent overrides + ... ? Or just multiple game-state subsystems
  each writing their own copy? Worth understanding for repair work.
- The **DC-vs-original-DXHR** content additions. We've noticed
  `cdc::InstanceTable::LoadFromStream` exists in both at similar RVAs
  (DC: `0xECEB0`, dxhr: `0xED260`, ~+0x1000 offset). The buggy bounds
  check in `LoadDrmResourceById` is **identical in both binaries**,
  so it's a Crystal Dynamics engine bug that predates DC. The
  original release just doesn't trigger it because saves don't get
  corrupted there.

---

## How to use this document

- **New session starting**: read top to bottom in 10 minutes; the
  RVA tables let you jump directly to the function you need.
- **Adding a new hook**: pick the matching subsystem section, add a
  row to the table with the 🪝 marker.
- **New crash to investigate**: check the "Crash signatures" table
  first; if it's a known class you know the playbook.
- **New function decompiled**: add to the appropriate subsystem table.
  If it's a leaf function used by many others, list it in
  "Globals/utilities" instead.
- **Renaming in Ghidra**: also update the symbol name in this
  document so they stay in sync. Ghidra is the source of truth for
  the database; this file is the human-readable index.
