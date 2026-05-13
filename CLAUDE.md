# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A Windows `version.dll` proxy that hooks the engine of *Deus Ex: Human Revolution — Director's Cut* (DXHRDC.exe, 32-bit) to fix save-load crashes after ~30 hours of gameplay. The shipped engine is a Crystal Dynamics console port with a 512 MB hardcoded dlmalloc pool and many deserialization functions that mishandle corrupted save data. Goal: load corrupted saves, discard the bad fields, keep player progression/inventory.

**Three reference files live at the parent repo root:**
- **[SUMMARY.md](../../../SUMMARY.md)** — chronological narrative of the fix effort, ~80 KB. Read top-to-bottom for context.
- **[DXHRDC_engine_RE.md](../../../DXHRDC_engine_RE.md)** — function-map / RE knowledge base. Quick reference for "what does FUN_X do?" and "what's at RVA Y?". Use this when investigating a new crash or extending a hook.
- **[README.md](../../../README.md)** — older user-facing docs.

For non-trivial changes, read SUMMARY first. For "I just need to know about FUN_X" lookups, jump straight to DXHRDC_engine_RE.md.

### Current state (2026-05-07)

- **15 hooks installed** (1, 2, 3, 4, 5-fixed, 6, 7, 8, 9-LAA-fixed, 11, 12, 13, 14, 15). Hook 10 was removed as redundant.
- **GAMER23_4 (the late-Missing-Link save) now loads** — into a degraded state (no HUD, broken inventory/aug menus) but no longer crashes the process.
- **Save format mostly mapped**: zlib-compressed → fixed `0x23A000`-byte buffer; first 960 KB is player progression (99.98% identical between same-chapter saves); remaining 1.4 MB is per-session world state where corruption lives.
- **Hybrid graft experiment FAILED** (SUMMARY §11.1). Crashed at RVA `0x0020845E` with NULL+0xD8 deref, completely new crash chain, no hooks fired. **Progression header and world state are NOT independent** — they cross-reference each other. The hybrid created an inconsistent save: GAMER23 progression says "end of Missing Link" + GAMER63 world says "ship deck" → looked-up table is NULL.
- **Surgical patch is the next move**: take GAMER23 untouched, find uint32s in stack-address range (`0x02000000-0x0FFFFFFF`) within the world-state region (`0xF0000+`), overwrite with `0`. Same semantic as Hook 5's stream-exhaustion bailout, applied at the file level.
- The corruption mechanism is "uninitialized stack memory leaks into `InstanceTable->field_0x14` at save time, writer faithfully serializes garbage, loader trusts it" (SUMMARY §10.4). Likely correlates with non-lethal-takedown / accumulated ragdoll state.
- `pythonSaveRepair/save_repair_tool.py` exists with hybrid mode (now non-viable). Needs `--mode=patch` for the surgical approach.

## Standing instructions from the user

- **Do not change any files or folders without explicit permission.** This includes the `version_proxy.c` source. Discuss approach first, propose hooks, then change after the user agrees.
- **Do not touch files outside the project folder** `DXHRDC_memoryAllocHookFix/` (i.e. anywhere outside `E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\`).
- **GhidraMCP is required.** The MCP server exposes `mcp__ghidra__*` tools against a loaded DXHRDC.exe project. If those tools are unavailable, **stop and notify the user** — do not continue without them.
- **Do not trust SUMMARY.md notes 100%.** Re-verify any RVA, function meaning, or prologue you are about to act on by re-decompiling/disassembling in Ghidra. Notes can drift from the binary.
- **Explain proposed hooks/adjustments and ask the user to test** before iterating.

## Build / install / debug

The repo has no automated test or lint pipeline. Workflow is: edit C, build DLL, copy to game directory, run game, inspect log.

```bat
:: From "x86 Native Tools Command Prompt for VS 2022" in DXHRDC_memoryAllocHookFix\
cl /LD /O2 /GS- /W3 version_proxy.c /Fe:version.dll /link /DEF:version.def /MACHINE:X86
```

The Visual Studio solution `DXHRDC_memoryAllocHookFix.sln` builds the same target. Output must be a 32-bit DLL — the game is x86.

Install: copy `version.dll` next to `DXHRDC.exe` in the Steam install dir. Uninstall: delete it. Diagnostic log appears as `dxhr_memfix.log` next to the EXE; create an empty file `dxhr_memfix_console` next to the EXE to also get a real-time console window.

Optional: `python pythonPatchHeapSize/patch_heap_size.py DXHRDC.exe` patches the 512 MB heap reservation up to 1.5 GB (creates `.bak` automatically). Helps with legitimate large allocations but does not fix corrupted-save crashes alone.

## Architecture essentials

### Source layout

- `DXHRDC_memoryAllocHookFix/version_proxy.c` — **the active source**, ~1700 lines, all 10 hooks in one file.
- `DXHRDC_memoryAllocHookFix/version.def` — exports the 16 `version.dll` API names; `.def` is what gives clean undecorated exports on 32-bit MSVC (`__declspec(dllexport)` alone produces `_Name@N` decorations the game won't resolve).
- `DXHRDC_memoryAllocHookFix/pch.{c,h}`, `framework.h` — minimal precompiled header.
- `version_proxy*.c` in the parent repo root are historical snapshots (v0–v13). Do not edit them; they exist for diff purposes.
- `files/`, `files2/`, `*.zip` — older bundles for distribution. Not load-bearing.
- `compatible_modhook/` — a third-party modded `DFEngine.dll` alternative loader. Not currently used (the `version.dll` proxy is the active mechanism).

### Hook mechanism (one paragraph)

Each hook overwrites the first N bytes of a target function's prologue with `JMP rel32` to a detour. The stolen bytes are copied into an executable trampoline followed by `JMP target+N` so the original behavior remains callable. `__thiscall` targets are captured via `__fastcall(this, edx_unused, ...)`. `VirtualProtect` + `FlushInstructionCache` wrap installation. The DLL pins itself with `GET_MODULE_HANDLE_EX_FLAG_PIN` because the game calls `FreeLibrary(version.dll)` after a version probe.

### Allocator model (the part that keeps biting us)

The game has **two allocation paths** into the same dlmalloc pool:

```
Path A: Game → MemHeapAllocator::Allocate (0x1fdcc0)  → dlmalloc → OOM → GamePrintError (terminates)
Path B: Game → FUN_001fe4e0 (direct dlmalloc wrapper) → dlmalloc → returns NULL → caller logs/crashes
```

Hooks 2/3 cover Path A. Hook 10 covers Path B. Hook 1 suppresses `GamePrintError`'s `int 3` so the allocator can return NULL normally. Hook 4 must catch `Free` because handing a `VirtualAlloc`'d fallback pointer to dlmalloc corrupts the heap.

**Caveat to remember**: every VirtualAlloc'd fallback pointer is a foreign object in dlmalloc's bookkeeping. If the game ever passes one to dlrealloc, or coalesces neighbors, dlmalloc reads metadata that doesn't exist. Some current crashes (see SUMMARY §7) are consistent with this. Adding more allocator hooks is unlikely to be the right next move — replacing buggy *deserializers* (Hook 8 style) is.

### Deserialization hooks (the targeted fixes)

Three hook patterns we've used (and rough rules for which to use):

1. **Input-validation hook** (Hook 12 model). The hooked function reads
   a value (an index, an id, etc.); validate the value upfront against
   a known constraint and early-return on rejection. Best when the
   constraint is cheap to compute (table count via known global, etc.).

2. **Caller-aware substitution** (Hook 13 model). Hook a leaf function
   that has many legitimate callers; use `_ReturnAddress()` to detect
   calls from a specific buggy region and substitute a safe stub for
   those calls only. Other callers see unchanged behavior. Best when
   you can't change the function's global semantic but a specific code
   region needs different behavior.

3. **SEH wrap** (Hook 14 / Hook 15 model). Wrap the trampoline call in
   `__try/__except (EXCEPTION_EXECUTE_HANDLER)`; on fault log and
   return a sane default (e.g., 0 = "operation failed cleanly"). Best
   when the function already has multiple early-exit paths the caller
   handles, *or* when the bug is too tangled to validate inputs without
   reproducing the function's logic.

4. **Complete reimplementation** (Hook 8 model). Replace the function's
   body with a corrected version that calls back into the game's
   helpers. Best when the bug is a structural issue (infinite loop) and
   the function is small enough.

Specific hooks:
- **Hook 8** — `Hud::LoadActiveGroups` (RVA 0x0041e080) reimplements a
  `while(true)` loop that never terminates on truncated streams.
- **Hook 5** — caps the instance-table loop count, AND (post-fix in
  commit `fcb20dd`) early-returns when the stream can't fit the
  flag+count header (otherwise the original engine uses an
  uninitialized stack variable as the loop counter → 45M+ iterations).
- **Hooks 6/7** — blanket caps for `DynArray_PushBack_8bytes` and
  `DynArray4_PushBack` at 100000 elements. Blunt but bounded.
- **Hook 9** — `GetHeapCategoryName` sanitization (with LAA-correct
  upper bound `0xFFFEFFFF`).
- **Hook 11** — `BuildDrmFilename` filename-pointer sanitization (last
  line of defense against `_sprintf` walking garbage).
- **Hook 12** — `LoadDrmResourceById` index AND entry-value validation.
  The actual fix for the `0x1005` crash signature.
- **Hook 13** — caller-aware stub for `FUN_001a4c80` (covers the
  deserializer family at RVA 0x25Bxxx-0x25Exxx).
- **Hook 14** — SEH wrap around `FUN_00065180` (vtable-NULL deref).
- **Hook 15** — SEH wrap around
  `cdc::InstanceTable::RestoreInstance`. Reads many fields off a
  potentially-corrupt descriptor; SEH-catch returns 0 (function's own
  "give up on this instance" code).

### Key RVAs (verify in Ghidra before relying on them)

Allocator: `0x1fbc60` GamePrintError · `0x1fb660` GetHeapCategoryName · `0x1fdcc0` Allocate · `0x1fde30` AllocateAligned · `0x1fe010` Free · `0x1fe4e0` MemHeapAllocator::PrimaryAlloc (was misnamed "Path B" in old SUMMARY) · `0x1fcf90` dlmalloc · `0x1fcc00` dlfree · `0x1fce00` dlmalloc_GrowHeap · `0x2028b0` OSHeap::Init · `0x2029d0` OSHeap::sbrk.

Deserialization: `0x0eceb0` InstanceTable::LoadFromStream · `0x0ecc00` InstanceTable::SaveToStream · `0x0ecc80` InstanceTable::RestoreInstance · `0x41e080` Hud::LoadActiveGroups · `0x41de80` Hud::PushActiveGroup · `0x14ec40` DynArray4_PushBack · `0x2b0dd0` DynArray_PushBack_8bytes · `0x1385c0` ArrayCopyElements.

Resource lookup chain: `0x000a4240` BuildDrmFilename · `0x000edcc0` LoadDrmResourceById · `0x001a4c80` (lookup-by-id, 100+ callers) · `0x000ed8f0` (table reload from objectlist.txt).

Save system: `0x00408bb0` save-system command dispatcher (string verbs: `LoadExistingSavedGame`, `SaveNewGame`, `OverwriteExistingGame`, ...) · `0x0033cdd0` save-load state machine (allocates `0x23A000` buffer).

### Worktrees

The user works inside git worktrees at `.claude/worktrees/<name>/`. The worktree's working dir is what `pwd` returns; the parent repo root (`DXHRDC_memoryAllocHookFix/`) is three levels up. SUMMARY.md and README.md live in the parent repo root, not in worktrees.

## Calling-convention reference (because it's bitten us)

- 32-bit MSVC. `WINAPI` = `__stdcall`, decorates as `_Name@N` — `.def` strips the decoration.
- `__thiscall`: `this` in ECX, args on stack right-to-left, callee cleans (`RET imm16`).
- Capture `__thiscall` from C as `__fastcall(void* this_, void* edx_unused, ...)`.
- VirtualAlloc returns page-aligned (4096) memory — satisfies any game alignment requirement.
- `__try/__except` and `va_list` cannot live in the same function on MSVC; split into a helper.
- DXHRDC.exe is `/LARGEADDRESSAWARE` — user-mode addresses span up to `0xFFFEFFFF`, NOT `0x7FFFFFFF`. Use the wider bound when validating pointers.

## Save format reference

PC saves at `<SteamDir>/userdata/<userid>/238010/remote/`. The user has set up a junction at `<repoRoot>/238010/` so saves are accessible from the repo. Naming: `GAMER##_4` (player slots 1–99), `GAMEA1_4` (autosave), `GAMEQ1_4` (quicksave). The `_4` suffix is the language code (English).

Format quick reference:
- **zlib-compressed** (magic `78 9C`).
- Decompressed size: **fixed `0x23A000` = 2,334,720 bytes**. Matches the engine's `FUN_001ac850(0x23a000)` allocation.
- **No encryption, no checksum/signature.**
- **First 960 KB (`0x000000–0x0F0000`)** = player progression header (XP, augs, story flags, base inventory). Stable between consecutive saves in the same chapter (≪200 byte diff observed).
- **Remaining 1.4 MB (`0x0F0000` onward)** = per-session world state (instances, NPC positions, ragdolls). High variation between saves; **this is where the corruption lives.**
- Inventory records: `[ID 3B BE | 00 00 | DATA 2B | 00 00]` = 9 bytes each. Item IDs match the Xbox 360 save editor's IDs (e.g., painkillers `0x001F51`).
- Multiple snapshots per save (~6 redundant copies of inventory/aug data observed).

### Save-index constraint

The game uses a **save-index** that determines which slots are valid. We **cannot create a new save file** — slot creation must go through the index, and arbitrary new files may be ignored or break indexing. Save-slot replacement / repair must overwrite an existing slot. There is a small GitHub project addressing save-index modifications (link TODO).

Backup files (`*.bak`, `*_Backup`) exist for some slots and can be safely renamed-back.

### Reverse-engineering reference

The Xbox 360 save editor is decompiled in `Deus Ex Editor v3.6/`. Its `form1.cs` contains `ReadSTFS()`, `CacheOffsets()`, `ReadValues()`, and `WriteValues()` — read these to learn item IDs and field offsets the community already RE'd. The Xbox saves are STFS-wrapped; PC saves are not, but the inner `savegame.sav` format is largely the same (see SUMMARY §10).
