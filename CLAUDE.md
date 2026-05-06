# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A Windows `version.dll` proxy that hooks the engine of *Deus Ex: Human Revolution — Director's Cut* (DXHRDC.exe, 32-bit) to fix save-load crashes after ~30 hours of gameplay. The shipped engine is a Crystal Dynamics console port with a 512 MB hardcoded dlmalloc pool and several deserialization functions that mishandle corrupted save data. Goal: load corrupted saves, discard the bad fields, keep player progression/inventory.

**The exhaustive context is in [SUMMARY.md](../../../SUMMARY.md)** (in the parent repo root, ~30 KB). Read it before making any non-trivial change — it documents 10 hooks, 9 versions, the allocator architecture, the discovered game bugs, and the current known crash.

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

- **Hook 8 — `Hud::LoadActiveGroups` (0x0041e080)** is a complete reimplementation of a known-buggy game function whose `while(true)` loop never terminates on truncated streams. This is the model to follow for future fixes: identify the buggy deserializer, write a corrected version that calls back into the game's helpers (`PushActiveGroup` at 0x0041de80, etc.).
- Hooks 5/6/7 cap counts (50000 instances, 100000 array elements). They are blunter — useful to prevent runaway growth but may also reject legitimate large arrays.
- Hook 9 sanitizes `GetHeapCategoryName` return values so the printf path doesn't crash on a bad pointer.

### Key RVAs (verify in Ghidra before relying on them)

Allocator: `0x1fbc60` GamePrintError · `0x1fb660` GetHeapCategoryName · `0x1fdcc0` Allocate · `0x1fde30` AllocateAligned · `0x1fe010` Free · `0x1fe4e0` direct-dlmalloc wrapper · `0x1fcf90` dlmalloc · `0x1fcc00` dlfree · `0x1fce00` dlmalloc_GrowHeap · `0x2028b0` OSHeap::Init · `0x2029d0` OSHeap::sbrk.

Deserialization: `0x0eceb0` InstanceTable::LoadFromStream · `0x41e080` Hud::LoadActiveGroups · `0x41de80` Hud::PushActiveGroup · `0x14ec40` DynArray4_PushBack · `0x2b0dd0` DynArray_PushBack_8bytes · `0x1385c0` ArrayCopyElements.

### Worktrees

The user works inside git worktrees at `.claude/worktrees/<name>/`. The worktree's working dir is what `pwd` returns; the parent repo root (`DXHRDC_memoryAllocHookFix/`) is three levels up. SUMMARY.md and README.md live in the parent repo root, not in worktrees.

## Calling-convention reference (because it's bitten us)

- 32-bit MSVC. `WINAPI` = `__stdcall`, decorates as `_Name@N` — `.def` strips the decoration.
- `__thiscall`: `this` in ECX, args on stack right-to-left, callee cleans (`RET imm16`).
- Capture `__thiscall` from C as `__fastcall(void* this_, void* edx_unused, ...)`.
- VirtualAlloc returns page-aligned (4096) memory — satisfies any game alignment requirement.
- `__try/__except` and `va_list` cannot live in the same function on MSVC; split into a helper.
