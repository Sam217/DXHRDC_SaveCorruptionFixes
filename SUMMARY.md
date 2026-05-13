# Deus Ex: Human Revolution Director's Cut — Save Load Fix

> **Companion documents:**
> - [DXHRDC_engine_RE.md](DXHRDC_engine_RE.md) — RE knowledge base (function map, vtable layouts, crash signature catalog, etc.). **Use this for quick "what is RVA X?" lookups** rather than re-reading SUMMARY.
> - [CLAUDE.md](.claude/worktrees/bold-shamir-df882c/CLAUDE.md) — quick-start guide for new sessions.

## A Reverse Engineering Journey

This document chronicles the effort to fix a save-game loading crash in
*Deus Ex: Human Revolution — Director's Cut* (DXHRDC) after 30+ hours of
gameplay. The work involved Ghidra reverse engineering, inline hooking,
crash analysis, and iterative debugging across 10 hooks and 9 versions
of a proxy DLL.

---

## 1. The Problem

After extended gameplay (30+ hours), the game's save files become
corrupted in a way that prevents loading. Two symptoms manifest:

**Symptom A — Crash to Desktop (CTD):** The game crashes with an access
violation during save load. In earlier attempts (before this project),
several of these were bypassed by flipping conditional jumps (`JE`/`JZ`)
in a debugger, but each fix revealed the next crash.

**Symptom B — Out of Memory Error:** The game displays a message box:

```
ERROR: Out of memory, "Misc" requested 268435456 bytes (256.0 MB)
(187952176 total free (179.2 MB) (total free with fall back alloc 179.2 MB))
```

The game then shuts down and refuses to load the save file. All save
files from the last two levels of gameplay exhibit this behavior.

**Key constraints:**
- The EXE is already LARGEADDRESSAWARE (previous investigation confirmed)
- The game uses only ~1.2 GB of RAM despite having ~3.5 GB available
- Binary diffing of save files proved impractical — two nearly identical
  saves produce vastly different binary outputs
- The game is a 32-bit Xbox 360 port using Crystal Dynamics' engine
- The same engine and identical error are reported in Tomb Raider (2014)

---

## 2. Initial Analysis — The Allocator Architecture

### Tools used
- **Ghidra** (via MCP server) for static analysis and decompilation
- **Visual Studio 2022** debugger for runtime analysis
- **Python** for binary patching

### What we found

The game uses a custom **dlmalloc-based heap allocator** (Doug Lea's
malloc) operating within a pre-reserved virtual address space pool.
The allocator class hierarchy in namespace `cdc` (Crystal Dynamics Core):

```
cdc::OSHeap
  └─ Reserves VA space via VirtualAlloc(MEM_RESERVE) at startup
  └─ Provides sbrk-like growth within the reservation

cdc::MemHeapAllocator (extends dlmalloc)
  └─ Bin-based best-fit allocator within the OS heap
  └─ Fallback allocator chain
  └─ Error reporting via GamePrintError on OOM

cdc::ThreadSafeMemHeapAllocator
  └─ CriticalSection wrapper around MemHeapAllocator

cdc::GameHeapAllocator
  └─ Game-specific initialization
```

### Key functions identified and renamed in Ghidra

| RVA | Name | Purpose |
|-----|------|---------|
| `0x001fbc60` | `GamePrintError` | Format error → MessageBox → `int 3` (never returns) |
| `0x001fb660` | `GetHeapCategoryName` | Lookup category name by ID from table |
| `0x001fb890` | `AllocatorManager::Init` | Creates all heap instances |
| `0x001fcf90` | `dlmalloc` | Core best-fit allocator |
| `0x001fcc00` | `dlfree` | Core free with block coalescing |
| `0x001fce00` | `dlmalloc_GrowHeap` | Calls sbrk to expand the pool |
| `0x001fd930` | `dlmemalign` | Aligned allocation core |
| `0x001fdcc0` | `MemHeapAllocator::Allocate` | Main allocation entry point |
| `0x001fde30` | `MemHeapAllocator::AllocateAligned` | Aligned allocation entry |
| `0x001fe010` | `MemHeapAllocator::Free` | Main free entry point |
| `0x001fe310` | `ThreadSafeAlloc` | Lock + Allocate + Unlock |
| `0x001fe350` | `ThreadSafeAllocAligned` | Lock + AllocAligned + Unlock |
| `0x001fe460` | `GameHeapAllocator::Init` | Game heap setup |
| `0x001fe4e0` | (Direct dlmalloc wrapper) | Calls dlmalloc directly (Path B) |
| `0x001fe540` | (Allocator vtable wrapper) | Lock + Allocate with vtable dispatch |
| `0x002028b0` | `OSHeap::Init` | VirtualAlloc reservation |
| `0x002029d0` | `OSHeap::sbrk` | Bounded growth within reservation |
| `0x0014ec40` | `DynArray4_PushBack` | Dynamic array push (4-byte elements) |
| `0x002b0dd0` | `DynArray_PushBack_8bytes` | Dynamic array push (8-byte elements) |
| `0x001385c0` | `ArrayCopyElements` | Memory copy for array reallocation |
| `0x000eceb0` | `InstanceTable::LoadFromStream` | Deserialize game instances from save |
| `0x0041e080` | `Hud::LoadActiveGroups` | Deserialize HUD state from save |
| `0x0041de80` | `Hud::PushActiveGroup` | Add one HUD group entry |
| `0x001fbd30` | `CRC32_Compute` | CRC32 checksum calculation |

### Global data

```
DAT_015ed7b0    Global allocator manager
  +0x48         Pointer to resource allocator
  +0x4C         Pointer to main heap allocator instance
  +0xD4         Category name table (indexed by category ID)
```

---

## 3. Root Cause Discovery — The 512 MB Ceiling

### The smoking gun: OSHeap::Init

Inside `cdc::OSHeap::Init` (RVA `0x002028b0`), we found two hardcoded
constants that define the maximum size of the game's memory pool:

```c
// Primary: try to reserve 512 MB
reservedBase = VirtualAlloc(NULL, 0x20000000, MEM_RESERVE, PAGE_NOACCESS);
reservedSize = 0x20000000;   // stored at this+0x438

// Fallback: try 384 MB if 512 MB fails
if (reservedBase == NULL) {
    reservedBase = VirtualAlloc(NULL, 0x18000000, MEM_RESERVE, ...);
    reservedSize = 0x18000000;
}
```

And in `cdc::OSHeap::sbrk` (RVA `0x002029d0`):

```c
if (currentTop + delta > reservedBase + reservedSize) {
    return -1;   // CANNOT GROW — hard limit reached
}
```

**The game's entire heap is capped at 512 MB**, regardless of how much
address space is available. With LARGEADDRESSAWARE on 64-bit Windows,
there's ~3.5 GB available — the game just doesn't use it.

This is a classic **console port issue**: the Xbox 360 had 512 MB total
unified memory, so a 512 MB pool was generous. On PC, it's a straitjacket.

### Why Task Manager shows only ~1.2 GB

The 512 MB pool is just one component of the process's memory:

```
~28 MB    EXE image (.text + .rdata + .data + .shad + .rsrc)
~200 MB   Loaded DLLs (system + game)
~300 MB   GPU-mapped resources (D3D11 textures, buffers)
~512 MB   Game's custom dlmalloc pool  ← THE BOTTLENECK
~160 MB   Thread stacks, other allocations
─────────
~1.2 GB total (out of ~3.5 GB available)
```

### Binary patch: increase pool to 1.5 GB

A Python script (`patch_heap_size.py`) was created to patch 4 locations
(16 bytes total) in DXHRDC.exe:

| Location | Instruction | Old | New |
|----------|-------------|-----|-----|
| PUSH (VirtualAlloc size) | `68 00 00 00 20` | 512 MB | 1.5 GB |
| MOV (sbrk limit) | `C7 86 38 04 00 00 00 00 00 20` | 512 MB | 1.5 GB |
| PUSH (fallback size) | `68 00 00 00 18` | 384 MB | 1.25 GB |
| MOV (fallback limit) | `C7 86 38 04 00 00 00 00 00 18` | 384 MB | 1.25 GB |

Both PUSH and MOV must be patched because they serve different purposes:
the PUSH tells VirtualAlloc how much to reserve, while the MOV stores
the limit that sbrk checks before allowing growth.

**Result:** The patch alone did not fix the crash — increasing the pool
size helps with legitimate large allocations but doesn't address the
runaway allocation loops caused by save corruption (discovered later).

---

## 4. The Proxy DLL Approach

### Why a proxy DLL instead of binary patching

A previous attempt (in an earlier chat session) used code caves and
multi-location binary patches. It crashed on startup, likely because
byte values didn't match the exact binary version. The proxy DLL
approach has several advantages:

- **No EXE modification** — fully reversible by deleting the DLL
- **Robust** — works regardless of EXE base address (ASLR)
- **Extensible** — easy to add more hooks iteratively
- **Debuggable** — can compile in debug mode with VS2022

### How the proxy works

The DLL is named `version.dll` and placed next to `DXHRDC.exe`. Windows
loads DLLs from the application directory first, so the game loads our
DLL instead of the system's `version.dll`. Our DLL:

1. Loads the real `version.dll` from `System32` via `LoadLibraryW`
2. Exports the same 16 API functions, forwarding all calls to the real DLL
3. Installs inline hooks on game functions during `DLL_PROCESS_ATTACH`
4. Pins itself in memory (`GET_MODULE_HANDLE_EX_FLAG_PIN`) to survive
   `FreeLibrary` calls

### Export name decoration challenge

On 32-bit MSVC, `WINAPI` (`__stdcall`) decorates function names with
`_prefix` and `@N` suffix (e.g., `_VerQueryValueW@16`). The game
expects clean undecorated names. The `.def` file solves this — the
linker auto-strips the decoration when exporting via `.def`.

Key lessons learned:
- `__declspec(dllexport)` + `.def` file = duplicate exports (harmless)
- `.def` file alone = clean exports (preferred)
- Without `.def` = "Entry Point Not Found" error
- C++ compilation requires `extern "C"` or same-named functions

### The inline hook mechanism

Each hook overwrites the first N bytes (the "stolen bytes") of the
target function's prologue with a `JMP rel32` to our detour. The stolen
bytes are copied to an executable trampoline followed by a `JMP` back
to target+N:

```
Original function:              After hooking:
┌───────────────────┐           ┌───────────────────┐
│ PUSH EBP          │           │ JMP Hook_Func ────────┐
│ MOV EBP, ESP      │           │ NOP                │   │
│ AND ESP, 0xC0     │           │ ...rest unchanged  │   │
│ SUB ESP, 0x34     │           └───────────────────┘   │
│ ...               │                                    │
└───────────────────┘           ┌────────────────────────┘
                                ▼
                           Hook_Func (our code):
                             │ ... do stuff ...
                             │ call TRAMPOLINE ──────┐
                             │ ... check result ...  │
                             │ return                │
                             └───────────────────────│──
                                                     │
                           TRAMPOLINE:               │
                             ┌───────────────────────┘
                             ▼
                           ┌─────────────────────────┐
                           │ PUSH EBP      (stolen)  │
                           │ MOV EBP, ESP  (stolen)  │
                           │ AND ESP, 0xC0 (stolen)  │
                           │ JMP (original + 6) ─────────┐
                           └─────────────────────────┘   │
                                                          ▼
                           Original function + 6:
                           ┌───────────────────┐
                           │ SUB ESP, 0x34     │
                           │ ... continues     │
                           │ RET               │
                           └───────────────────┘
```

Critical implementation details:
- `VirtualProtect` is needed to make the code section writable
- `FlushInstructionCache` ensures the CPU sees the new instructions
- `__thiscall` is captured via `__fastcall` (ECX=this, EDX=unused)
- Stolen byte count must align to complete x86 instructions

---

## 5. The Hook Evolution — 10 Hooks Across 9 Versions

### Version 1.0 — Initial allocator hooks (Hooks 1-4)

**The core insight:** `GamePrintError` (Hook 1) NEVER RETURNS. It calls
`ExceptionHandlerQ_terminate()` + `int 3`. If we only hook the allocator,
the original function crashes internally before our hook gets the return
value. We must suppress the crash first.

**Hook 1 — GamePrintError** (RVA `0x001fbc60`, 8 bytes stolen)
- Purpose: Suppress OOM crash so the allocator can return NULL normally
- Mechanism: When `g_suppressOOM` flag is set, log the error and return
  instead of terminating
- Why needed: Without this, Hooks 2-3 never get to provide fallback memory

**Hook 2 — MemHeapAllocator::Allocate** (RVA `0x001fdcc0`, 6 bytes stolen)
- Purpose: VirtualAlloc fallback when internal pool exhausted
- Mechanism: Call original via trampoline, if NULL returned and size > 0,
  allocate from OS via VirtualAlloc
- Tracking: All fallback allocations recorded for proper cleanup

**Hook 3 — MemHeapAllocator::AllocateAligned** (RVA `0x001fde30`, 6 bytes)
- Purpose: Same fallback for aligned allocation path
- Note: VirtualAlloc returns page-aligned memory (4096 bytes), which
  satisfies any game alignment requirement (4, 8, 16, 64, 128...)

**Hook 4 — MemHeapAllocator::Free** (RVA `0x001fe010`, 6 bytes stolen)
- Purpose: Correctly free VirtualAlloc'd blocks
- Mechanism: Check if pointer is in our tracking table; if yes,
  VirtualFree; if no, delegate to original dlmalloc free
- Why critical: Passing a VirtualAlloc'd pointer to dlmalloc would
  corrupt the game's internal heap

### Version 1.1-1.2 — DLL lifecycle fixes

**Problem:** The game loads `version.dll` temporarily to check its own
file version, then calls `FreeLibrary`. Our DLL unloads, but the hooks
remain in the game's code — jumping to freed memory.

**Fix:** Pin the DLL using `GetModuleHandleExW` with
`GET_MODULE_HANDLE_EX_FLAG_PIN`. This makes `FreeLibrary` a no-op for
our DLL while the process lives. The DLL is automatically cleaned up
when the process exits.

**Logging improvements:**
- Console output (opt-in via `dxhr_memfix_console` trigger file)
- Log file kept open for entire process lifetime
- Module enumeration at startup (all loaded DLLs with address ranges)
- Module name resolution in stack traces (`DLLname.dll+0xOffset`)

### Version 1.3 — The doubling pattern discovered

**What the logs revealed:**

```
Allocate(268435456 = 256 MB) → fallback VirtualAlloc
Allocate(536870912 = 512 MB) → fallback VirtualAlloc
Allocate(1073741824 = 1024 MB) → fallback VirtualAlloc
Allocate(-2147483648 = 2048 MB) → signed overflow!
→ ArrayCopyElements(NULL, ...) → ACCESS VIOLATION at 0x00000004
```

A data structure was doubling its capacity each time it ran out of space
(128→256→512→1024→2048 MB), eventually overflowing a signed 32-bit int.
When the overflow made size negative, our hook's `if (size > 0)` check
failed, we returned NULL, and the caller crashed trying to copy into NULL.

**Hook 5 — InstanceTable::LoadFromStream** (RVA `0x000eceb0`, 5 bytes)
- Purpose: Cap the instance count read from save stream
- Mechanism: Peek at the 4-byte count before calling original; if > 50000,
  patch it in-place, call original, then fix up stream position
- Result: Did NOT trigger — the doubling came from a different caller

**Hook 6 — DynArray_PushBack_8bytes** (RVA `0x002b0dd0`, 5 bytes)
- Purpose: Universal growth cap for 8-byte-element dynamic arrays
- Mechanism: Check array element count; if > 100000, refuse the push
- Result: Also did NOT trigger — wrong template instantiation

### Version 1.4-1.5 — Stack trace improvements

**Problem:** `CaptureStackBackTrace` only returned 2 frames because the
game's functions (compiled with `/O2`) use Frame Pointer Omission (FPO).
The EBP chain breaks at the first game function.

**Improvements:**
- Unicode WinAPI throughout (MODULEENTRY32W, GetModuleFileNameW, etc.)
- MSVC safe functions (_vsnprintf_s, _snprintf_s, sprintf_s)
- Module name resolution: `"VERSION.dll+0x1190E"` instead of `"external DLL"`
- Vectored Exception Handler with ESP-based stack scanning (same heuristic
  as Visual Studio debugger) for crash diagnostics

**Key discovery:** The "external DLL" in the stack trace was actually our
own `VERSION.dll` (the proxy). The doubling allocations were happening
INSIDE our Hook_Allocate — frame #0 was our hook's return address from
LogStackTrace. The real caller was deeper but invisible due to FPO.

### Version 1.6 — VS debugger reveals the true caller chain

We attached the VS2022 debugger and captured a full stack trace
that `CaptureStackBackTrace` couldn't provide:

```
#0  RVA 0x001385DD   ArrayCopyElements         ← crash (write to NULL+4)
#1  RVA 0x0014EC90   DynArray4_PushBack        ← 4-byte element variant!
#2  RVA 0x0041DECA   Hud::PushActiveGroup      ← called each iteration
#3  RVA 0x0041E0DE   Hud::LoadActiveGroups     ← while-loop from save stream
```

**The root cause was DynArray4_PushBack** — a **4-byte element** variant
of the DynArray push function, completely separate from the 8-byte
variant we hooked in Hook 6.

**Hook 7 — DynArray4_PushBack** (RVA `0x0014ec40`, 5 bytes stolen)
- Purpose: Cap growth for 4-byte-element dynamic arrays
- Same mechanism as Hook 6 but for the correct template instantiation

### Version 1.7 — The infinite loop

**Problem:** Hook 7 successfully prevented the memory explosion, but the
game hung — the caller's loop ran infinitely because our hook made
`PushBack` a no-op (returning immediately without growing the array),
but the loop had no other exit condition.

**Analysis of the game bug in Hud::LoadActiveGroups (RVA 0x0041e080):**

```c
// GAME BUG — simplified:
value = initial_nonzero_value;
while (true) {
    if (stream_has_data()) {
        value = read_4_bytes(stream);    // updates value
    }
    // if stream exhausted: THIS BLOCK IS SKIPPED
    // value retains its last non-zero reading

    if (value == 0) break;   // ← NEVER triggers after exhaustion!
    PushActiveGroup(value);  // ← runs forever
}
```

When the save stream is exhausted without containing a zero terminator,
the last non-zero value persists, the exit condition never triggers, and
the loop runs forever. This is a **bug in the game's code** — the loop
should also break when the stream runs out.

**Hook 8 — LoadActiveGroups** (RVA `0x0041e080`, 6 bytes stolen)
- Purpose: Replace the buggy loop with a safe reimplementation
- Mechanism: Complete function replacement that adds two safety exits:
  1. Break when stream is exhausted (`consumed >= total`)
  2. Break after 1000 iterations (with stream draining)
- Result: Successfully prevented the infinite loop

### Version 1.8 — Corrupted format arguments

**Problem:** After fixing the infinite loop, a new crash appeared at
RVA `0x00641FDE` — inside the game's statically-linked `__output_l`
(VS2008 CRT's printf implementation). It crashed reading address
`0x00001005` as a string.

**Analysis:** The allocation error formatting path passes a category
name pointer (from `GetHeapCategoryName`) as a `%s` argument. When the
category ID is corrupted, the function returns garbage like `0x00001005`.
The game's own `__vsnprintf` tries to read that "string" and crashes.

**Fix:** SEH protection around `_vsnprintf_s` in `Hook_GamePrintError`.

**Result:** The crash persisted — it wasn't going through our hook at all.
The crash was in the GAME'S statically-linked CRT (inside DXHRDC.exe),
not in our DLL's CRT (ucrtbased.dll). There are no `VERSION.dll` frames
in the crash stack.

### Version 1.9 — Two allocation paths

**The discovery of Path B:** The game has two separate allocation paths:

```
Path A (hooked since v1.0):
  Game code → Allocate (0x001fdcc0) → dlmalloc → OOM → GamePrintError
                ↑ HOOKED                                  ↑ HOOKED

Path B (completely invisible until now):
  Game code → FUN_001fe4e0 → dlmalloc DIRECTLY → NULL → error log → crash
                               ↑ bypasses ALL our hooks
```

Path B calls `dlmalloc` directly at `0x001fcf90`, never touching our
hooked `Allocate`. When dlmalloc fails, the caller tries to log the
error through a different formatting path (not `GamePrintError`), using
the corrupted category name, and crashes in the game's own CRT.

**Hook 9 — GetHeapCategoryName** (RVA `0x001fb660`, 5 bytes stolen)
- Purpose: Sanitize category name pointers at the source
- Mechanism: Call original, validate returned pointer (range check +
  `IsBadReadPtr`), return `"(bad_cat)"` for invalid pointers
- Why this fixes all paths: Every error formatter gets the name from
  this function, regardless of which allocation path or error function
  they use

**Hook 10 — Direct dlmalloc wrapper** (RVA `0x001fe4e0`, 5 bytes stolen)
- Purpose: VirtualAlloc fallback for Path B
- Mechanism: Same pattern as Hook 2 — call original, if NULL and size
  is valid, fall back to VirtualAlloc from OS

---

## 6. Technical Lessons Learned

### x86 calling conventions and hooking
- `__thiscall` passes `this` in ECX; captured via `__fastcall` wrapper
- `__cdecl` does not clean stack (caller responsibility)
- `__stdcall` adds `_Name@N` decoration on 32-bit MSVC
- `.def` files are the only clean way to export undecorated names

### Stack walking challenges
- `CaptureStackBackTrace` requires EBP frame chains
- Game code compiled with `/O2` uses Frame Pointer Omission (FPO)
- ESP-based stack scanning (heuristic) works but includes stale values
- VS debugger uses more sophisticated heuristic analysis
- Manual EBP chain walking fails when EBP is used as a data register

### Memory management architecture
- dlmalloc uses bins (small=exact-size, large=sorted-tree) for free blocks
- Console ports often have hardcoded pool sizes from Xbox 360 era
- Multiple allocation paths can exist (vtable dispatch, direct calls)
- VirtualAlloc returns page-aligned memory (4096), satisfying any
  game alignment

### DLL proxy techniques
- Pin with `GET_MODULE_HANDLE_EX_FLAG_PIN` to survive FreeLibrary
- `GetProcAddress` always uses ANSI names (even on Unicode systems)
- Forwarding stubs must match exact calling convention and arg count
- SEH (`__try/__except`) cannot be in the same function as va_list
  on MSVC — use a helper function

### Debugging corrupted data
- Corrupted save data causes cascading failures at multiple points
- Each fix reveals the next corruption layer
- Array doubling with corrupted counts is a common failure mode
- Infinite loops arise when stream termination conditions rely on
  sentinel values that may be absent in corrupted data

---

## 7. Current Status

### What works
- The game starts and loads normally
- All 10 hooks install correctly (prologue verification passes)
- The infinite HUD loop is terminated cleanly
- DynArray growth is capped to prevent memory explosion
- VirtualAlloc fallback catches OOM on both allocation paths
- Exception logging provides full crash diagnostics

### Current state
- The Hooks 9 and 10 (v1.9) do not resolve the remaining crash at
  `0x00641FDE` (corrupted category name in `__output_l`)
- The access violation at reading address 0x1005 still persists and stems from a callstack containing our hook 10 (EXE base = 0x00440000):
    -    DXHRDC.exe!00a81fde()	Unknown
    - 	[Frames below may be incorrect and/or missing, no symbols loaded for DXHRDC.exe]	
    - 	ntdll.dll!_NtAllocateVirtualMemory@24()	Unknown
    - 	KernelBase.dll!75186900()	Unknown
    - 	DXHRDC.exe!0063ce54()	Unknown
    - 	DXHRDC.exe!0063d393()	Unknown
    - 	DXHRDC.exe!0063e534()	Unknown
    - >	version.dll!Hook_DirectMalloc(void * this_, void * edx_, int size, int extra) Line 1170	C
    - 	DXHRDC.exe!0063dcf0()	Unknown
    - 	DXHRDC.exe!006480a0()	Unknown
    - 	DXHRDC.exe!006492dc()	Unknown
    - 	DXHRDC.exe!00649e80()	Unknown
    - 	DXHRDC.exe!00670443()	Unknown
    - 	DXHRDC.exe!0061c5e5()	Unknown
    - 	DXHRDC.exe!0061d964()	Unknown
    - 	DXHRDC.exe!008763e1()	Unknown
    - 	DXHRDC.exe!0061cf43()	Unknown
    - 	DXHRDC.exe!006ec681()	Unknown
    - 	ntdll.dll!_NtSetInformationProcess@16()	Unknown
    - 	DXHRDC.exe!004df82c()	Unknown
    - 	DXHRDC.exe!00730075()	Unknown

### Files

| File | Purpose |
|------|---------|
| `version_proxy.c` | Proxy DLL source (all 10 hooks, ~1500 lines) |
| `version.def` | Export definitions (16 version.dll API functions) |
| `build.bat` | VS2022 build script |
| `patch_heap_size.py` | Binary patch for heap reservation (512→1536 MB) |

### How to build and install

1. Build: Open x86 Native Tools Command Prompt for VS 2022, run `build.bat`
   (or compile in VS2022 IDE as a 32-bit DLL project with `/EHa`)
2. Patch: `python patch_heap_size.py DXHRDC.exe`
3. Install: Copy `version.dll` and `version.def` to game directory
4. Debug console: Create empty file `dxhr_memfix_console` next to EXE
5. Uninstall: Delete `version.dll`, restore `DXHRDC.exe` from `.bak`

---

## 8. Architecture Diagram

```
                    ┌─────────────────────────────────────┐
                    │         DXHRDC.exe Process           │
                    │                                      │
  ┌─────────────────┤  Save File (corrupted)               │
  │                 │    │                                  │
  │  ┌──────────────┤    ▼                                  │
  │  │              │  Hud::LoadActiveGroups ─── Hook 8     │
  │  │  Hook 5      │    │ (infinite loop fix)              │
  │  │  (count cap) │    ▼                                  │
  │  │              │  Hud::PushActiveGroup                 │
  │  │              │    │                                  │
  │  │              │    ▼                                  │
  │  │  Hook 7      │  DynArray4_PushBack ──── Hook 7      │
  │  │  (growth cap)│    │ (element cap)                    │
  │  │              │    │                                  │
  │  │  Hook 6      │  DynArray_PushBack_8 ─── Hook 6      │
  │  │  (growth cap)│    │ (element cap)                    │
  │  │              │    ▼                                  │
  │  │              │  ┌─── PATH A ───┐  ┌── PATH B ──┐    │
  │  │              │  │  Allocate    │  │ Direct     │    │
  │  │  Hook 2,3    │  │  Hook 2/3   │  │ Malloc     │    │
  │  │  (fallback)  │  │  (fallback) │  │ Hook 10    │    │
  │  │              │  └──────┬──────┘  └─────┬──────┘    │
  │  │              │         │               │            │
  │  │              │         ▼               ▼            │
  │  │              │      dlmalloc ◄─────────┘            │
  │  │              │         │                             │
  │  │              │         ▼                             │
  │  │              │      GrowHeap → sbrk                 │
  │  │              │         │                             │
  │  │              │    ┌────┴────┐                        │
  │  │              │    │  OOM?   │                        │
  │  │              │    └────┬────┘                        │
  │  │              │         │ yes                         │
  │  │              │         ▼                             │
  │  │  Hook 9      │  GetHeapCategoryName ── Hook 9       │
  │  │  (sanitize)  │    │ (pointer validation)            │
  │  │              │    ▼                                  │
  │  │  Hook 1      │  GamePrintError ─────── Hook 1       │
  │  │  (suppress)  │    │ (suppress OOM crash)            │
  │  │              │    ▼                                  │
  │  │  Hook 4      │  VirtualAlloc fallback               │
  │  │  (free track)│    (from Hooks 2, 3, or 10)          │
  │  │              │                                      │
  │  │  VEH         │  Vectored Exception Handler          │
  │  │  (crash log) │    (ESP-based stack scan)            │
  │  └──────────────┤                                      │
  │                 └─────────────────────────────────────┘
  │
  │  version.dll (proxy)
  │  ┌────────────────────────────────────┐
  └──┤  Loads real version.dll from System32
     │  Forwards 16 API functions
     │  Installs 10 inline hooks
     │  Pins itself in memory
     │  Logs to dxhr_memfix.log + console
     └────────────────────────────────────┘
```

---

## 9. Iteration after v1.9 — what we learned

Everything in §1–§8 was the v1.9 baseline. The work after that is summarized
below in chronological order; commit messages on the
`claude/bold-shamir-df882c` branch contain the per-step rationale.

### 9.1 Hook 10 removed — wasn't a separate "Path B"

GhidraMCP xref analysis showed `FUN_001fe4e0` has only **one** xref — from a
vtable data slot at `0x006a1c50` (= `MemHeapAllocator::vtable[+0x5c]`).
Every call to it already goes through `MemHeapAllocator::Allocate` →
vtable dispatch. Hook 10 was double-hooking the same chain, mutating the
tracking table twice per allocation, and contributing nothing.

**The "Path B" theory in §5/v1.9 was wrong.** There is no separate direct
caller of `FUN_001fe4e0`. Removing Hook 10 didn't change the persistent
0x1005 crash signature — confirming the crash was *not* at the allocator
layer.

Commit: `1e3adc5`.

### 9.2 The 0x1005 crash was never an OOM — it's `_sprintf("%s%s.drm", …, 0x1005)`

The actual crash at RVA `0x00641FDE` is inside the statically-linked
**`__output_l`** (VS 2008 CRT), specifically the `%s` walker:

```
00641fdd: DEC ECX
00641fde: CMP byte ptr [EAX], 0x0   ; ★ EAX = 0x1005 → access violation
00641fe1: JZ  ...
00641fe3: INC EAX
00641fe4: CMP ECX, ESI
00641fe6: JNZ 0x00641fdd
```

Walking back the stack revealed the real chain:

```
FUN_0022ff60 (level loader)
  └── FUN_00209a30 (instance restoration)
      └── FUN_00209290
          └── FUN_00207ef0 (instance creation)
              └── ... game code ...
                  └── FUN_000ede40 (thin wrapper)
                      └── LoadDrmResourceById (FUN_000edcc0)
                          ├── buggy bounds check calls FUN_000ed8f0 but does NOT abort
                          ├── ECX = table[idx*8]                ← OOB read with bad idx
                          └── BuildDrmFilename(buf, ECX = 0x1005)   [RVA 0x000a4240]
                              └── _sprintf(buf, "%s%s.drm", prefix, 0x1005)
                                  └── __output_l → CRASH walking 0x1005 as a string
```

The "0x1005 = bad pointer" had a beautifully simple explanation later:
**something is calling `LoadDrmResourceById(idx=0)`**. The table read for
`idx=0` is `tableBase[0]` = the table's `max_id` field (4101 for this
level = 0x1005). Hook 12 confirmed this empirically.

### 9.3 Hooks 11 & 12 — LoadDrmResourceById + BuildDrmFilename (commits `5250c66`, `c0f4eea`, `84ace72`)

Two complementary hooks on the resource-lookup chain:

- **Hook 11** (`BuildDrmFilename` at RVA `0x000a4240`): validates the
  filename pointer (`< 0x10000` or `> 0xFFFEFFFF` or `IsBadReadPtr`)
  before calling `_sprintf`. On rejection writes empty string. Catches the
  immediate sprintf crash regardless of upstream cause. **Safety net.**

- **Hook 12** (`LoadDrmResourceById` at RVA `0x000edcc0`): the *real*
  fix. Validates `idx` against the global resource-table count via the
  same indirection the engine uses (`*(int **)(0x00a9a43c)` →
  `[+0x18][+0]`). Also validates the **entry value** at `tableBase[idx*8]`
  (because `idx <= max_id` doesn't guarantee the slot is populated —
  unpopulated slots keep the init value `0x00000000`). On either reject
  reason the function early-returns without allocating the cache slot or
  calling `FUN_001a7590`.

Verified the exact same broken bounds check exists in dxhr.exe (original
DXHR) at RVA 0x4ED260 — **this is a Crystal Dynamics engine bug that
predates DC**, original release just never had save data corrupt enough
to trigger an OOB index.

### 9.4 The LAA bound bug (commit `82eb67d`)

Hook 11's first version used a `> 0x7FFE0000` upper bound. DXHRDC.exe is
`/LARGEADDRESSAWARE` so user-mode addresses span up to `0xFFFEFFFF` on
64-bit Windows. The strict bound rejected legitimate high-heap pointers
like `0x81C5D5B5` at startup, causing a "Can't open file" fatal. Same
bug existed in Hook 9; both fixed.

### 9.5 GamePrintError = the engine's `assert()` (commits `71a1e8e`, `b846d9d`)

Briefly tried to suppress "Can't open file" errors in Hook 1 to let the
load continue past Hook 11's rejections. **Discovered the engine treats
`GamePrintError` as `assert()`** — callers don't NULL-check after the
call because they assume `int 3` already terminated the process. Our
suppression turned the assert into a no-op return, exposing every
implicit-NULL-deref the engine never had to guard against. **Reverted**
the suppression and pivoted to fixing the corruption upstream instead.

### 9.6 Hook 13 — caller-aware safe stub for FUN_001a4c80 (commits `c4a6fcb`, `a59ee4b`)

The next layer after `LoadDrmResourceById` was a family of save
deserializers at RVA `0x25Bxxx-0x25Exxx` (FUN_0025bb50, _25c580,
_25cb50, _25dcc0, _25de90, _25df50, _25e010, _25e090, _25e390). They
all call `FUN_001a4c80` (a global object-table lookup, returns NULL on
miss) and **all share the same engine bug**: NULL guard followed by
dereference outside the guard. Confirmed instances:

```
FUN_0025cb50:                              FUN_0025e090 (excerpt):
  piVar3 = FUN_001a4c80(param_1);            puVar8 = FUN_001a4c80(uVar12);
  if (piVar3[6] != 0) { ... }                if (puVar8 != NULL) {
  ↑ piVar3[6] = NULL+0x18 → CRASH                uVar9 = *puVar8;  // safe
                                                 if (uVar9 != 0) ...
                                                 if (uVar9 <= uVar10) goto SKIP;
                                             }
                                             // ★ falls through with puVar8 NULL
                                             if (*(... + puVar8[1]) != 0) {
                                             ↑ puVar8[1] = NULL+0x04 → CRASH
```

`FUN_001a4c80` has **100+ legitimate callers** across the engine; can't
change its NULL semantic globally. Hook 13 uses `_ReturnAddress()` to
detect calls originating inside the deserializer family RA range
`[0x25B000, 0x260000)` and substitutes a static 16-uint zero stub for
those specific calls. With `*stub == 0`, the affected functions take
their existing "skip" branches before reaching the buggy deref.

### 9.7 Hook 14 — SEH wrapper around FUN_00065180 (commit `0fe0180`)

Past the deserializer family, the next crash was at `FUN_00065180` RVA
`0x00065180` — same engine pattern, even worse: lookup-table-read +
*tail-call into the result's vtable* with no NULL guard:

```
MOV ECX, [EDX + EBX*4]       ; ECX = piVar1 = table[idx*4]
MOV [ESI+0x28], ECX           ; this->field_0x28  = piVar1
MOV [ESI+0x15c], ECX          ; this->field_0x15c = piVar1
MOV EDX, [ECX]                ; ★ EDX = *piVar1 — CRASH at NULL+0
... tail call vtable[+0x58](piVar1, stream)
```

Couldn't reuse Hook 13's approach (we don't know the target table size at
runtime). Used `__try/__except` SEH wrapper around the trampoline call.
Tail-call analysis confirmed stack effects balance (vfunc returns
directly to OUR hook's caller via `RET 0x4`; SEH unwinds cleanly to our
handler on exception). Side effect: `this->field_0x28` and `+0x15c` are
NULL after the catch — that's actually beneficial for downstream
NULL-check paths.

### 9.8 VEH improvement (commit `9a7342b`)

Hook 14's SEH catch worked but the *next* crash wasn't logged. The old
VEH used a one-shot flag (to prevent infinite spam when an exception
re-fires unhandled). Replaced with: track last-logged exception address +
a counter (cap 5). Same EIP re-firing → suppress. New EIP under cap →
log. This made the next crash visible.

### 9.9 Hook 15 — SEH wrap cdc::InstanceTable::RestoreInstance (commit `7665176`)

The function the project was originally trying to make work. It reads
many fields off the instance descriptor (`param_1 + 0x11c`, `+0x120`,
`+0x128`, `+0x12c`, ...). Corrupted descriptors cause faults; the
function **already** has multiple `return 0` early-exit paths and the
caller checks the return value, so SEH-catch + return 0 produces the
**same outcome the function already produces for known-bad inputs** —
skip this instance, continue the load.

This matches the project's stated goal exactly: "discard the
corrupted/garbage data, keep all the valid save data still loaded".

### 9.10 Hook 5 fix — stream exhaustion (commit `fcb20dd`)

After Hook 15 the load stopped *crashing* but **infinite-looped** — 45M
iterations through the SEH catch. The disassembly revealed that
`cdc::InstanceTable::LoadFromStream` initializes its loop counter as
`puVar1 = param_1` (a stack variable's address, ~`0x02BDxxxx ≈ 45M`)
*before* conditionally reading the count from stream. **When the stream
is exhausted (`pos+5 > total`), the count read is skipped and the loop
runs `45M+` times.**

Hook 5's existing peek-and-cap logic had `if (pos+5 <= total)` guard —
when stream was exhausted, we silently didn't cap and let the original
run into its bug. Fix: detect exhaustion explicitly and **early-return
from our hook entirely** without calling the original. Same outcome the
engine would produce if it had a sane "no data → no instances" path.

### 9.11 Final outcome

After all the above, **GAMER23_4 (the late-Missing-Link save) loads** —
but in a degraded state: HUD doesn't work, inventory/aug menus fail,
abilities inaccessible, weapon switch broken after a few attempts. The
weapons are *initially* remembered, suggesting some sections of the save
are intact while others were written as garbage at save time.

We **stopped patching crashes** at this point and pivoted to
understanding the save data itself.

---

## 10. Save format reverse engineering

### 10.1 The Xbox 360 save editor (Deus Ex Editor v3.6)

Saved in `Deus Ex Editor v3.6/` in the project root. .NET app written
for Xbox 360 saves. We decompiled `form1.cs` (~19K lines).

Key findings:
- Xbox saves are **STFS containers** (Secure Transacted File System) with
  a `savegame.sav` blob inside. PC saves don't use STFS.
- The editor's `ReadSTFS` extracts `savegame.sav`, then `CacheOffsets()` +
  `ReadValues()` parse it via **byte-pattern search**, not structured
  parsing.
- Pattern for exp/praxis: search for the 12-byte sequence
  `00 01 2D 75 00 01 2D 83 00 01 2D 7B` (three big-endian aug IDs); exp
  is at `marker - 12`, praxis at `marker - 8` (both int32 BE).
- Pattern for inventory items: each item has a 5-byte marker like
  `00 1F 51 01 01` (painkillers); count is at `marker + 5` (uint16 BE).
- The editor scans 4× for the aug pattern (4 separate occurrences =
  redundant snapshots in the save).

**Critical implication**: saves are not encrypted (otherwise pattern
search wouldn't work).

### 10.2 PC save format

PC saves at `<Steam>/userdata/<userid>/238010/remote/GAMER##_4` (also
`GAMEA1_4` for autosave, `GAMEQ1_4` for quicksave). The `_4` suffix is
the language code (English).

Verified with Python on the user's saves:

| Property | Value |
|---|---|
| Compression | **zlib** (`78 9C` magic) |
| Decompressed size | **exactly `0x23A000` = 2,334,720 bytes** (matches engine's `FUN_001ac850(0x23a000)` allocation) |
| Encryption | none |
| Checksum/signature | none |
| Header field | first 4 bytes = LE uint32 = "data length" (varies per save) |
| Inventory record | **9 bytes**: `[ID 3B BE | 00 00 | DATA 2B | 00 00]` |
| Inventory separator | `00 00` (PC) vs `01 01` (Xbox) — only difference |
| Item IDs | same as Xbox (e.g., painkillers `0x001F51`) |
| Snapshots | **multiple per file** (we observed 11× painkillers occurrences = ~6 redundant snapshots) |

PC saves are essentially the same engine format as Xbox, just **without
STFS wrapping** and with `00 00` separator bytes instead of `01 01`. Aug
IDs differ from original DXHR (DC has different/added augs).

### 10.3 Working save vs broken save diff

Compared GAMER63_4 (last known working, ship deck pre-Rifleman-Bank) vs
GAMER23_4 (broken, end of Missing Link, just before Singapore loadscreen):

```
total bytes differ: 845,014 (36.2%)
First 0xF0000 (960 KB) of file: only 160 bytes diff
  — concentrated in:
    0x000000: 69 bytes  (header / playtime / save metadata)
    0x001000: 8 bytes
    0x003000: 59 bytes
    0x005000: 24 bytes
0xF0000 onward: 50–95% diff per 16KB chunk (the "world state" region)
```

**The first 960 KB is the player progression area (XP, story flags, augs,
base inventory)** — 99.98% identical between two saves in the same
chapter. The remaining 1.4 MB is per-session world state (instances, NPC
positions, ragdoll state) — **this is where the corruption lives**.

### 10.4 Corruption mechanism (theory)

- The engine writer `cdc::InstanceTable::SaveToStream` (RVA 0x000ECC00) is
  **structurally sane** — reads from well-defined fields and writes them
  faithfully via the standard two-pass count-then-write pattern.
- But the writer reads `count = this->field_0x14` directly. If that
  field is **garbage in memory at save time**, the writer faithfully
  serializes the garbage.
- The "huge counts" we observed (45M, 13M, 5M) are all in the
  **stack-address range** (`0x02XXXXXX–0x0FXXXXXX`). The crash registers
  at runtime correlated tightly: `EBX = 0x00CCD544` was just **1724
  bytes** away from the corrupted id `0x0CCDC00`. **They're in the same
  stack frame.**
- **Conclusion**: an uninitialized stack variable in some calling code
  leaks into `InstanceTable->field_0x14`. The writer dutifully serializes
  it. The bug propagates write-side → file → read-side → crash.
- **Internet community theory**: corruption correlates with non-lethal
  takedowns / accumulated ragdoll state. Plausible — neutralized NPCs
  leave persistent "knocked out" instance state that grows over time.
  At some point an instance bookkeeping field is left uninitialized
  before save.

### 10.5 The save-system entry chain

For future investigation:

```
FUN_00408bb0  string-dispatched save-system command handler:
              "RequestSlotInfo", "RequestDeviceInfo",
              "GetCurrentDLCPackId", "IsGameInProgress",
              "SaveNewGame", "OverwriteExistingGame",
              "LoadExistingSavedGame", "LoadSavedGameThumbnail",
              "DeleteSavedGame"

FUN_0033ca30  validates slot metadata; returns 1 → "Damaged Save Game" dialog
FUN_001af980  reads slot-info flag (used by validator)
FUN_0033cdd0  state machine; allocates 0x23A000 buffer and calls
              FUN_001ac850 / FUN_002032f0 / FUN_001b0450 for I/O

cdc::InstanceTable::SaveToStream  RVA 0x000ECC00  (writer, vtable+0)
cdc::InstanceTable::LoadFromStream RVA 0x000ECEB0  (loader,  vtable+4)
                                                   (already Hook 5)
cdc::InstanceTable::RestoreInstance RVA 0x000ECC80 (already Hook 15)
```

### 10.6 The save-index constraint

The game uses a **save index** that determines which slots are valid. We
**cannot create a new save file** — slot creation must go through the
index, and arbitrary new files may be ignored or break indexing. Save
slot replacement / repair must overwrite an existing slot. There's a
small GitHub project addressing save-index modifications (TODO: link).

`GAMER##_4` slots are **player save slots** (1–99, named in-game).
`GAMEA1_4` is autosave. `GAMEQ1_4` is quicksave. Backup files (`*.bak`,
`*_Backup`) exist for some slots.

---

## 11. Current status (2026-05-07)

### What works
- 15 hooks installed (1, 2, 3, 4, 5 fixed, 6, 7, 8, 9 LAA-fixed, 11, 12, 13, 14, 15)
- Hook 10 removed as redundant
- VEH logs first 5 distinct exceptions instead of just one
- **GAMER23_4 (latest broken save) now LOADS** — into a degraded
  game state but no longer crashes
- Older corrupted saves now reach predictable crash points (variable per
  save, but all in the per-session world-state region)
- Build pipeline: VS 2022 solution; `version.dll` auto-copied to game dir
  via PostBuildEvent (user-local, not committed)

### What doesn't work
- Game UI is partially broken in the loaded GAMER23 (no HUD, inventory
  fails, augs inaccessible, weapon switch breaks after a few uses)
- Other corrupted saves still crash (different crash signatures per save)

### Decision points
- **Save repair tool feasibility**: requires surgical patching, not graft.
- Initial **hybrid graft hypothesis FAILED** (see §11.1). Progression
  header and world state are **not independent** — they cross-reference
  each other. The 99.98% header identity between GAMER23 and GAMER63
  just means saves in the same chapter have nearly identical headers,
  not that headers from one save can be combined with arbitrary world
  state from another.
- **Surgical patch** remains viable: identify the specific corrupted
  uint32 field(s) (stack-address-range values, `0x02000000-0x0FFFFFFF`)
  in broken save's world state and overwrite with `0`. Same idea as
  Hook 5's cap, applied at the file level.

### Files
| File | Purpose |
|------|---------|
| `DXHRDC_memoryAllocHookFix/version_proxy.c` | All 15 hooks (~2.2K lines) |
| `DXHRDC_memoryAllocHookFix/version.def` | 16 version.dll API exports |
| `pythonPatchHeapSize/patch_heap_size.py` | Optional 512→1.5GB heap patch |
| `Deus Ex Editor v3.6/` | Decompiled .NET save editor (Xbox 360 saves) |
| `238010/remote/GAMER##_4` | User's saves (junction → Steam userdata) |
| `dxhr_memfix.log` | Symlink to game dir's log |
| `CLAUDE.md` | Quick-start guide for new sessions (in worktree) |

### How to resume work after losing this conversation

1. Read this `SUMMARY.md` and `CLAUDE.md` (in `.claude/worktrees/<name>/`).
2. Verify GhidraMCP is connected; load DXHRDC.exe (and optionally
   dxhr.exe for cross-comparison).
3. `git log --oneline` on the active branch shows the per-step history
   with detailed commit messages.
4. If continuing the save-repair direction: see §11.1 (hybrid failed,
   surgical patch is the next move). The repair tool already exists at
   `pythonSaveRepair/save_repair_tool.py` — it currently implements
   hybrid graft mode (broken now-confirmed-non-viable). Add a
   `--mode=patch` that scans the world-state region (`0xF0000+`) for
   uint32s in stack-address range (`0x02000000-0x0FFFFFFF`) and zeros
   them.
5. If continuing the loader-hook direction: each new crash gives
   approximately the same level of work — find function by RVA in
   Ghidra, decide between input-validation hook (Hook 12 model),
   caller-aware substitution (Hook 13 model), or SEH wrap (Hook 14/15
   model).

---

## 11.1 Hybrid graft experiment — FAILED (2026-05-07)

### What we tried

Built `pythonSaveRepair/save_repair_tool.py` to combine GAMER23's
first 960 KB (progression header) + GAMER63's world state from
`0xF0000` onwards. Wrote the result to GAMER22_4 (with timestamped
backup of original at
`GAMER22_4_pre_repair_20260507_075945`). Compressed back to zlib
default level (78 9C magic), roundtrip-verified byte-identical.

### What happened

Game crashed during load with a **completely different crash chain**
than anything seen before:

```
Crash:   RVA 0x0020845E
Op:      READ at [NULL + 0xD8]
EAX=0    EBX=0x77    ECX=0x02648BC8    EDX=0
ESI=0x023E7F10    EDI=0x77

Stack scan:
  #0: RVA 0x0020845E   <-- CRASH
  #1: RVA 0x00209C10
  #2: RVA 0x000D250A   (familiar)
  #3: RVA 0x00409B22   <-- new function not in any prior chain
  #4: RVA 0x00230443   (FUN_0022ff60 = level loader, familiar)
```

**No hooks fired** — no `LoadActiveGroups` exhaustion, no Hook 13
substitutions, no `LoadFromStream` skip. The hybrid load went
straight from the level loader into a previously-unknown NULL deref.

### Interpretation

`EBX=0x77, EDI=0x77` — the same value 0x77 (=119 decimal) in two
registers strongly suggests an **index** that's looking up a
**NULL table**. The "0xD8" offset is a struct field access from
that NULL table.

The hybrid created an **inconsistent save**: GAMER23's progression
header says "Adam is at end-of-Missing-Link" while GAMER63's world
state says "Adam is on the ship deck". The level loader sets Adam's
location/state per progression, looks it up in tables built from
world state, finds NULL. The two halves cross-reference each other.

### Lesson learned

The 99.98% byte identity between GAMER23 and GAMER63 in the first
960 KB **does NOT mean the regions are independent**. It just means
saves in the same chapter have nearly identical headers (only ~160
bytes change between same-chapter saves — likely playtime, save
metadata, perhaps a few story flags). But cross-combining with
**different chapter** world state produces an inconsistent reference
graph.

The save format is more interconnected than the per-byte diff
suggests. Headers and world state share at least one shared index
space (the 0x77 / NULL-table-lookup at the crash site).

### Implication for repair strategy

**Hybrid graft mode in the repair tool is non-viable.**

The next iteration should pursue **surgical patching** instead:
- Take GAMER23 untouched (preserves all its location/progression data
  consistently).
- In the world-state region (`0xF0000+`), find every uint32 in the
  stack-address range (`0x02000000-0x0FFFFFFF`).
- Overwrite those uint32s with `0` (= "no instances of this kind"),
  same semantic as Hook 5's stream-exhaustion bail-out.
- Game loads GAMER23's full state with the corrupt counters
  neutralized.

This is essentially "Hook 5's logic, applied to the file before
load instead of at load time".

GAMER22_4 currently still contains the failed hybrid. To restore the
original, copy `GAMER22_4_pre_repair_20260507_075945` back. The
pre-existing `GAMER22_4_Backup` is also untouched.


## 11.2 Forensic byte-diff investigation (2026-05-13)

After the hybrid-graft failure and the stack-address scan (Phase A1)
disproved the "surgical zero-patch" hypothesis (every save legitimately
contains 19K–38K uint32s in `0x02xxxxxx–0x0Fxxxxxx` because the engine
serializes integers as **big-endian on disk** — Xbox 360 PowerPC
legacy), we pivoted to a pure byte-diff between known-corrupt and
known-clean save pairs to localize the corruption.

### 11.2.1 Tooling

Three Python tools in `pythonSaveRepair/`:
- `diff_pair.py <save_a> <save_b>` — generic byte-diff, area-name
  extraction at `0x5045`, range bucketing into progression header
  (`<0xF0000`) and world state (`≥0xF0000`), top-N largest world-state
  ranges plus stack/heap-range uint32 LE sniff per range.
- `diff_prog_zoom.py` — full hex+ASCII context for progression-header
  diffs (one-shot GAMER50/51).
- `analyze_suspect_regions.py` — drills into specific world-state
  regions with per-2KB byte-class statistics (`%zero`, `%FF`,
  `%print`), and a targeted painkiller-count change search.

All saves at `<repo>/238010/<userid>/238010/remote/`.

### 11.2.2 Three save pairs analyzed

| Pair | Same area? | Playtime apart | Outcome |
|------|------------|----------------|---------|
| GAMER50 (corrupt) ↔ GAMER51 (self-healed) | No (area transition) | 18 min | Progression header **bit-identical except** file checksum, area-name string, time counter, Adam's XYZ position float, orientation. 13.15% world-state differs (legitimate gameplay). |
| GAMER51 (clean) ↔ GAMER53 (crashes) | Yes (`port_2a`) | ~21 s | 15.42% differs; world-state still noisy. Progression-header showed `0x50c3: 01→00` flag flip + a 32-bit time counter +1.5M + redundant snapshots at `0x2800` stride. |
| GAMER51 (clean) ↔ GAMER25 (newly corrupt) | Yes (`port_2a`) | 15 m of movement + painkillers hacked 4→12 | **10.10% differs** — tightest pair. Localized corruption to TWO world-state regions: `0x1f8a6f` (96 KB) and `0x211355` (24 KB). Statistically uniform "25.0% zero / 25.0% printable" fill across 20+ consecutive 2KB windows in the corrupt save — the signature of a **runaway writer loop**. |

### 11.2.3 Headline finding

**Progression data is fully intact in corrupt saves.** GAMER50's
progression header (offsets `0x0–0xF0000`) is byte-identical to
GAMER51's, except for: file checksum, area-name, area-header timestamps,
Adam's position/orientation floats. XP, praxis points, inventory,
augmentations — every byte the same.

This kills two earlier worries:
- Saves are NOT lossy on progression data.
- The visible in-game brokenness (HUD, doors, augs not firing) is
  **misrender of intact data**, not data loss.

The corruption lives entirely in the world-state region. Specifically,
in the `cdc::InstanceTable` save sub-streams owned by deferred-lighting
scene entities.

### 11.2.4 Painkiller hack 4→12: failed locator + key negative result

We had a controlled change between GAMER51 (painkillers=4) and GAMER25
(hacked to 12 via CheatEngine, then saved). Searched for:
- The 3-byte ID `00 1F 51` (Painkillers per the Xbox 360 form1.cs).
- Any uint16 BE/LE offset where GAMER51 reads 4 and GAMER25 reads 12.

Results:
- Painkillers ID `00 1F 51` appears 8 times in GAMER51 and 6 times in
  GAMER25; offsets mostly different between the saves; **none** of the
  occurrences have `00 04` (GAMER51) or `00 0C` (GAMER25) at the offsets
  the Xbox 360 editor expects (`<ID>01`, `<ID>0101`).
- BE-uint16 sweep over the whole buffer: 8 offsets where (GAMER51=4,
  GAMER25=12); none in progression header.

**Conclusion: the dnSpy/Xbox-360 inventory format does NOT apply to PC
saves.** The PC layout stores count separately from the item ID,
indexed by slot number (confirmed later via Ghidra; see §11.4).


## 11.3 CheatEngine: inventory access points

Once the dnSpy patterns failed, we ran CheatEngine on the live game to
find runtime addresses for Painkillers and used "find what reads/writes"
to get the engine's actual access RVAs.

| RVA (`DXHRDC.exe+`) | What | Operand | Notes |
|---------------------|------|---------|-------|
| `0x003F012A` | Reads painkiller count when opening inventory menu | `MOVZX/MOV ECX, [EAX+06]` | UI-display struct, **count at +6 (uint16)**. Inside `FUN_003efe70` (an "AddItem" UI dispatcher). |
| `0x0037611A` | Writes painkiller count when consuming items | `MOV [EAX+...], reg` (via `param_1_00 + slot*0x28 + 0x0e`) | **Primary inventory storage**: 40-byte records, count at offset `0x0e` within each record. Inside `FUN_003760f0`. |

Painkiller count is **uint16** (2 bytes) — initial 32-bit scan failed,
16-bit scan succeeded.

The two access sites operate on different struct layouts: an
intermediate UI struct (count at +6) and the primary inventory storage
(40-byte records, count at +0x0e). The `[eax+06]` in CheatEngine is the
UI-side intermediary, not where the canonical count lives.

CheatEngine pointer-scan was attempted but no reliable static base was
captured this session. Deferred — Ghidra's static decompile gave enough
to proceed without it.


## 11.4 Ghidra: InstanceTable subsystem confirmed

Decompiled the three pivotal functions via GhidraMCP. The Ghidra
project loads `DXHRDC.exe` with image base `0x00000000`, so CheatEngine
RVAs map directly to Ghidra addresses.

### 11.4.1 `cdc::InstanceTable::SaveToStream` — RVA `0x000ECC00`

```c
void cdc::InstanceTable::SaveToStream(this, stream) {
    write_byte(stream, *(byte*)(this + 4));                 // 1B type flag
    uVar1 = *(uint *)(this + 0x14);                          // count
    write_uint32(stream, uVar1);
    for (uVar2 = 0; uVar2 < uVar1; uVar2++) {
        write_uint32(stream,
            *(uint*)(*(int*)(this + 0x1c) + uVar2 * 8));     // entry idx
    }
}
```

Confirmed exactly as SUMMARY §10.4 predicted: `[1B flag][4B count]
[count × 4B index]`. Records in the source buffer at `this+0x1c` are
8-byte stride, but only the first 4 bytes (the index) are written.

### 11.4.2 `cdc::InstanceTable::LoadFromStream` — RVA `0x000ECEB0`

```c
puVar1 = param_1;                                            // ← stack ptr leak
puVar3 = param_1;
if (*param_1 + 4 <= param_1[1]) {                            // stream has 4 bytes?
    puVar1 = *(uint **)param_1[2];                           // read count (only if room)
    ...
}
for (; puVar1 != (uint*)0; puVar1 = (uint*)((int)puVar1 - 1)) {
    if (*param_1 + 4 <= param_1[1]) puVar3 = read_uint32(stream);
    iVar2 = RestoreInstance((int)puVar3 * 0x130 + *(int*)(param_1_00 + 0x10));
    if (iVar2 != 0) DynArray_PushBack_8bytes(&local_8);
}
```

The bug already documented in `DXHRDC_engine_RE.md`: `puVar1` is
initialized to the stack pointer (~`0x02BDxxxx` ≈ 45M) BEFORE the
conditional count-read. If stream is exhausted at count-read, `puVar1`
keeps its initial garbage value and the loop runs ~45M times.

Each iteration's index `puVar3` is multiplied by `0x130 = 304` and
added to the records base at `this+0x10` to get an instance pointer
passed to `RestoreInstance`. **Records are 304 bytes** = the canonical
"deferred light instance" struct size.

### 11.4.3 `cdc::InstanceTable::RestoreInstance` — RVA `0x000ECC80`

Restores ONE 304-byte instance from a description: `FUN_000efe30`,
`FUN_000edbc0`, `FUN_0020aaf0`, sets bit `0x200` at `iVar4+0x168`,
calls `FUN_00206240`, etc. Not symmetric with SaveToStream — that
function only writes indices, while RestoreInstance instantiates a
full object from a static description table indexed by the saved
index.

### 11.4.4 The InstanceTable struct (32 bytes)

From the constructor at RVA `0x000ECF60` (`FUN_000ecf60`):

```c
*param_1_00 = cdc::DeferredLightComponent::vftable;          // [+0x00] vtable ptr
*(byte*)(param_1_00 + 1) = 1;                                // [+0x04] type flag = 1
param_1_00[2] = param_1;                                      // [+0x08] context ptr
param_1_00[3] = *(u32*)(**(int**)(param_1 + 8) + 300);        // [+0x0c] derived from ctx
param_1_00[4] = *(u32*)(**(int**)(param_1 + 8) + 0x130);      // [+0x10] records base (304B stride)
param_1_00[5] = 0;                                            // [+0x14] count = 0
param_1_00[6] = 0;                                            // [+0x18] capacity = 0
param_1_00[7] = 7;                                            // [+0x1c] buffer (sentinel literal 7)
```

| Offset | Field | Notes |
|--------|-------|-------|
| `+0x00` | vtable ptr | `cdc::DeferredLightComponent::vftable`; SaveToStream slot at `DAT_006955C4`, LoadFromStream slot at `DAT_006955C8`. |
| `+0x04` | type flag (byte) | Constructor sets to `1`. SaveToStream serializes it. |
| `+0x08` | context ptr | Points to owning entity context. |
| `+0x0c` | derived | From `context->300`. |
| `+0x10` | records base ptr | Points to array of **304-byte** instance records. |
| `+0x14` | **count** | DynArray<8-byte-pair> count. **This is the field that gets corrupted.** |
| `+0x18` | capacity | DynArray capacity. |
| `+0x1c` | buffer ptr | DynArray buffer of **8-byte (idx, instance_ptr) pairs**. Constructor sentinel = literal `7`; real ptr installed on first PushBack. |

### 11.4.5 Owner: per-scene-entity InstanceTable at offset `+0x30c`

From the scene-entity constructor `FUN_002093b0` (RVA `0x002093B0`):

```c
if (*(int*)(**(int**)(param_1 + 8) + 300) != 0) {
    iVar3 = MemHeapAlloc(0x20, 0);                            // alloc 32 bytes
    if (iVar3 != 0) uVar5 = FUN_000ecf60(param_1);            // = InstanceTable ctor
    *(int*)(param_1 + 0x30c) = uVar5;                          // stored at entity+0x30c
}
```

Symmetric destruction in `FUN_00208880` (RVA `0x00208880`):
```c
iVar4 = param_1[0xc3];                                          // param_1[0xc3]*4 = 0x30c
param_1[0xc3] = 0;
if (iVar4 != 0) {
    FUN_000ecfb0();                                             // dtor at RVA 0x000ECFB0
    MemHeapFree(iVar4);
}
```

So **every "deferred-light-capable" scene entity owns its own 32-byte
InstanceTable at `entity+0x30c`**. The game has many such entities;
each has an independent count. Multiple corruption sites possible.

### 11.4.6 Vtable layout (`DAT_006955C4`)

The two adjacent xref hits confirm the vtable structure:
- `006955C4` → SaveToStream (`0x000ECC00`)
- `006955C8` → LoadFromStream (`0x000ECEB0`)

Other slots exist (the constructor writes a full vtable pointer, not
just two slots) but were not enumerated this session.


## 11.5 Two-bug model finalized

The previous "field_0x14 stack-leak" theory (SUMMARY §10.4) is partly
right but missed a second bug. The full picture is **two stacked bugs**:

### Bug A — Writer-side corruption (root cause; still unfixed)

During gameplay, the `count` field at `instance_table+0x14` of one or
more deferred-light scene entities is corrupted to a garbage value
(hundreds of thousands to tens of millions). When SaveToStream runs, it
**faithfully serializes** that garbage count and then iterates that many
times, reading 4 bytes per iteration from progressively-further memory
past the actual buffer end at `this+0x1c`. The stream eventually fills
up.

This is what produces the 96 KB + 24 KB **statistically-uniform
anomalous regions** in GAMER25's world-state (see §11.2.2). The 25.0%
zero / 25.0% printable pattern is the signature of out-of-bounds reads
into structured-but-unrelated memory being dumped to the save stream.

The corruption is deterministic in the sense that progression header
remains untouched, but non-deterministic in the sense that GAMER51 and
GAMER25 (15 m apart in `port_2a`) differ by 10% in world state — the
writer corrupts a different mix of fields each time.

**Mechanism not yet identified.** Likely candidates:
- Stack-leak into adjacent InstanceTable struct via an uninitialized
  local variable somewhere in the gameplay update path.
- Out-of-bounds write from an unrelated allocation that lands on
  `entity+0x30c+0x14`.
- Use-after-free where a recycled entity slot's `+0x30c` field still
  points to a now-corrupted 32-byte block.

### Bug B — Loader-side amplification (mitigated by Hook 5)

`cdc::InstanceTable::LoadFromStream` initializes its count variable
`puVar1` to a stack pointer BEFORE conditionally reading the count
from the stream. If the stream is exhausted at the point the count
should be read, `puVar1` retains its initial value (~45M) and the
restore loop iterates that many times.

This is the bug Hook 5 (`fcb20dd`) caught. The hook detects
`pos+5 > total` and skips the call entirely, preventing the crash but
leaving that subsystem's state empty.

### How they stack on a load

1. Corrupt save's first InstanceTable serializes ~100 KB of garbage
   indices, overconsuming the world-state sub-stream allocated to it.
2. The next InstanceTable in the deserialization chain finds the
   stream already exhausted.
3. Without Hook 5: garbage count is read from uninitialized stack,
   loop spins 45M times calling `RestoreInstance` with bad pointers
   → crash.
4. With Hook 5: skip the call. Subsystem state is empty. HUD,
   inventory menu, doors, augmentation triggers all fail because they
   depend on light-instance state that was never restored.

### Why this matches the in-game symptoms

- HUD doesn't render: HUD draws are gated on certain light/scene
  instances being present.
- Doors don't open: interaction prompts rely on entity instance
  registry.
- Augmentations don't fire: the higher-jump aug's effect requires
  the InstanceTable for the player's effect-component to be live.

All three are downstream of empty InstanceTables.


## 11.6 Decision: Path B (preventive) + Path C (root cause)

Three options were on the table at end of session:

- **Path A — Continue Ghidra RE to find writer bug.** High effort,
  uncertain payoff; the writer-side leak source could be anywhere in
  the gameplay tick.
- **Path B — Hook 16: save-time validator.** Hook
  `cdc::InstanceTable::SaveToStream` at RVA `0x000ECC00`. Before
  calling the original, validate `*(uint*)(this+0x14)`. If
  `> MAX_INSTANCES` (e.g., 50000) OR in stack/heap address windows,
  clamp to `0`. Prevents new corrupt saves from being created.
  ~60 lines of C, mirrors Hook 5's logic.
- **Path C — CheatEngine memory-write breakpoint.** Find a live
  InstanceTable struct in a running game, set a write breakpoint on
  the count field at `entity+0x30c+0x14`, play until corruption
  strikes. Reveals the exact instruction that writes garbage.

**Chosen path: B + C in parallel** at next session. B gives the user
working saves going forward (existing saves remain broken until
re-played past bad spots). C gives the root cause we need to fix the
upstream bug entirely.

### Practical next steps (for next session)

1. **Implement Hook 16** in `version_proxy.c`:
   - Hook `cdc::InstanceTable::SaveToStream` at RVA `0x000ECC00`.
   - Prologue stolen bytes: TBD (need disassembly of first 5+ bytes).
   - In the hook: read `*(uint*)(this + 0x14)`; if it's `> 50000` OR
     in `0x02000000–0x0FFFFFFF` (stack range) OR `0x10000000–0x1FFFFFFF`
     (heap range), log + clamp to 0 in-place before passing through.
   - Also log `_ReturnAddress()` and a snapshot of nearby fields so we
     correlate corruption with chapter/area as the user plays.
2. **Memory-write breakpoint hunt** in CheatEngine:
   - Load a clean save, find any scene entity with `entity[0x30c] != 0`
     (a deferred-light entity).
   - Inspect `entity[0x30c] + 0x14` — should be a small uint.
   - Set "find what writes to this address" breakpoint.
   - Play 5–10 min in an area known to corrupt. When the breakpoint
     fires on a write of a garbage value, the disassembly shows the
     leaking instruction.
3. **Tooling cleanup**: `diff_pair.py` and `analyze_suspect_regions.py`
   are session diagnostics — keep as-is, no integration into
   `save_repair_tool.py` yet.

### What's not on the table anymore

- File-level hybrid graft of progression+world-state regions (§11.1).
- Surgical stack-address zero-patch (§10.4 / Phase A1) — disproved
  because legitimate BE-encoded small ints saturate that address
  window.
- Reading inventory from the save via dnSpy/Xbox-360 patterns
  (§11.2.4) — PC format is structurally different (40-byte records,
  count at +0x0e, indexed by slot rather than co-located with ID).
  **(Note: this referred to the IN-MEMORY layout per CheatEngine; the
  ON-DISK PC format is a separate, still-undocumented serialization
  — see §11.9 / §11.10.)**
- ~~Reconstructing a working save by transplanting progression onto a
  clean modhook-debug-menu donor (Phase B from original plan). Now
  unnecessary because progression is intact in the corrupt saves;
  fixing the loader path (Hook 16 + maybe Hook 5 tightening) lets
  the existing corrupt saves load without losing data.~~ **Retracted
  in §11.9: only the ~960 KB progression header survives intact; the
  inventory/ammo/equipped-weapons on PC live in world state and are
  partly destroyed by the runaway writer. Phase B (donor + injection)
  is back on the table.**

---

## 11.7 Phase A1 scanners — falsified (2026-05-13 / 2026-05-14)

The "Phase A1" surgical-patch hypothesis from the original plan died on
contact with data. Two successive scanner designs were both falsified;
both are documented here so they don't get re-invented.

### 11.7.1 Stack/heap-range uint32 scanner (`--mode=scan`)

**Hypothesis** (§10.4): corrupted `InstanceTable->field_0x14` values
all sit in stack address window `0x02000000–0x0FFFFFFF` or heap window
`0x10000000–0x1FFFFFFF`. A read-only scan over 4-byte-aligned uint32
LE in the decompressed save buffer should expose:
- where corruption lives (cluster of hits in world state);
- when corruption began (chronological progression across saves);
- which saves are salvageable (low/zero hit count in the progression
  header).

**Result: hypothesis falsified.** `--mode=scan --scan-all` across 102
saves shows:

- Every save — including the very first (GAMER26, 2025-11-01) and the
  known-loadable GAMER51 — has 14,000–29,000 stack-range hits in world
  state.
- The progression header has a stable 4,500–5,000 stack-range hits
  per save, with almost no variance over six months of play.
- Hit count is uncorrelated with corruption status. Clean GAMER51 has
  19,762 world-state hits; corrupt GAMER25 has 15,079; corrupt GAMER23
  has 25,637.

Interpretation: the address windows are not "suspicious values" — they
are legitimate engine data (item IDs, hash values, encoded floats,
small denormalized values, etc.) that incidentally falls in those
numeric ranges. Per the byte-class signature work (§11.7.2), some of
this data even has a perfectly uniform structure that mimics a
runaway-writer dump.

**Bonus byproduct: GAMER6_4 stands out.** It's the only save in 102
with **zero** world-state hits in either window, 1,117 stack-range hits
in progression header (vs. ~4,700 elsewhere), and zero heap-range hits.
This confirms GAMER6_4 (created via the modhook debug menu / map
selector) is a structurally near-empty save — uniquely qualified to
serve as a clean donor for Phase B grafts.

### 11.7.2 Byte-class anomaly scanner (`--mode=scan-anomalies`)

**Hypothesis**: the runaway-writer signature in the byte-diff analysis
of §11.2 was a uniform 25.0%/25.0% zero/printable distribution across
2 KB windows. Slide a 2 KB window across world state, flag windows
with that signature, merge contiguous flagged windows into regions.

**Result: signature is real, but it ALSO occurs in clean saves at
~34 KB per save.** Detail:

- GAMER25 (corrupt) flags two regions: one at `0x1ac000–0x1b4800`
  (~34 KB) AND one at `0x1fb000–0x203800` (~34 KB).
- GAMER51 (clean) flags one region at exactly `0x1ac000–0x1b4800`
  — the SAME offsets as GAMER25's first region.
- Cross-save scan: every save except GAMER6_4 has at least one ~34 KB
  region. Region offsets move with session state (e.g. saves
  GAMER71–87 all show their one region at `0x10f000`; saves
  GAMER21/3/4/7/30 share `0x14dc00`).

Interpretation: a 34 KB block of small-integer engine data (likely
deferred-light instance arrays per the InstanceTable subsystem of
§11.4) is **structurally** uniform 25/25 — it's not corruption, it's
what some engine arrays look like serialized. The ACTUAL corruption in
GAMER25 is the SECOND region at `0x1fb000`, which GAMER51 lacks.

Region-count alone is not a clean classifier: GAMER50 (crashes) has 2
regions, GAMER51 (loads) has 1, GAMER53 (crashes) has 1, GAMER23
(crashes) has 1. A reliable offline detector requires per-area baseline
comparison, which we have not built.

### 11.7.3 The one part that survived: corrupt-region content in GAMER25

When inspected with raw hex dumps (`evidence_check.py`), the GAMER25
region starting at `0x1fb000` contains the 4-byte sequence
`00 63 1f 01` **repeated literally**:

```
GAMER25 @ 0x1fb000: 00 63 1f 01 00 63 1f 01 00 63 1f 01 00 63 1f 01 ...
                    (continues for ~34 KB)
GAMER51 @ 0x1fb000: 00 00 01 cd 27 00 00 b4 0e 00 00 01 ca 27 00 00 ...
                    (structured 8-byte engine records)
```

This is unambiguously runaway-writer output. The **exact boundaries**
of the corruption are NOT pinpointed by byte-diff alone — diff density
runs 60–86% across a wider band — but the byte-class signature plus
the literal byte-pattern repetition locate the core of the dump at
`0x1fb000`. A corollary: the prior "second region at `0x211355`"
claim in §11.2 is weaker than reported; only one such region is
clearly identifiable by the scan-anomalies detector. Treat the
`0x211355` claim as provisional.


## 11.8 Inventory is in world state on PC (NOT progression header)

The most consequential finding of the session. Falsifies a load-bearing
assumption from §11.5/§11.6.

### 11.8.1 Setup

- GAMER51 — clean, painkiller count = 4 (confirmed in-game).
- GAMER25 — corrupt, painkiller count = 12 (hacked 4 → 12 via
  CheatEngine just before the save).
- Both in area `sha_city_port_2a` (§11.10), saved ~30 min apart.

### 11.8.2 Direct byte-diff: progression header

`decode_painkiller_count.py` enumerates all byte differences between
GAMER51 and GAMER25 in the 0–0xF0000 progression-header region,
EXCLUDING the corrupted world-state band that we already know about.
The result:

| offset | length | GAMER51 | GAMER25 | plausible meaning |
|---|---|---|---|---|
| `0x0` | 3 | `ac c0 20` | `38 ad 22` | save-file header / outer hash |
| `0x50c3` | 1 | `01` | `00` | flag |
| `0x50c8` | 5 | `93 f7 e6 07 39` | `ab cb fb 07 5f` | sequential — looks like FILETIME-encoded save timestamp |
| `0x50d8` | 2 | `d4 a3` | `d6 a4` | counter or sub-checksum |
| `0x3eb6a` | 3 | `33 c6 68` | `19 27 ac` | hash |

**FIVE ranges total. No range looks like a payload field; all read as
timestamps, counters, or hashes.** No offset has GAMER51=4 ∧
GAMER25=12 in any encoding (u8 / u16 BE/LE / u32 BE/LE).

### 11.8.3 Direct byte-diff: world state

In contrast, the world state (≥0xF0000) — even excluding the known
corruption regions at `0x1ac000–0x1b4800` and `0x1fb000–0x203800` —
has **189,945 differing bytes** between GAMER51 and GAMER25,
collapsed into **2,616 contiguous diff ranges**. The actual inventory
delta lives somewhere in this haystack.

### 11.8.4 Confirmation via the form1.cs reader (`--mode=read`)

The XP/praxis/inventory reader ported from Deus Ex Editor v3.6
(form1.cs) was run against GAMER5, GAMER6, GAMER23, GAMER25, GAMER51:

- **`XP_PRAXIS_MAGIC`** (the 12-byte three-item-ID anchor used to
  locate the four redundant XP/praxis snapshots) — **0 matches in
  every save.** The Xbox 360 anchor pattern simply does not exist in
  PC saves.
- **All 40 catalogued inventory item IDs** (Painkillers, ammos, augs,
  etc.) — **absent in every save.** The Xbox 360 9-byte
  `[ID|01|01|count_be|00|00]` and `[ID|01|count_be|00|00]` record
  formats do not appear on PC.

### 11.8.5 Implication

We have **no working decoder for PC progression / inventory** today.
Previous notes in `DXHRDC_engine_RE.md` (Subsystem 9 — Inventory PC
layout) describe the IN-MEMORY layout per CheatEngine — 40-byte
records, count uint16 at +0x0e — but the on-disk serialization is
*not* a memory dump of those records. It is a separate, currently
unmapped engine-side serialization format.

This invalidates several earlier plan branches:

- **Phase B with progression injection** depends on a working
  inventory decoder. We don't have one.
- **"Progression is intact" reassurance** (§11.6 wrap-up) only holds
  for the ~0xF0000 progression header. Inventory, ammo, equipped
  weapons, and likely other player-state are in world state and at
  least partly destroyed when the runaway writer hits.
- **"GAMER5_prog + GAMER6_world graft"** would lose inventory, since
  inventory lives in the part being replaced.


## 11.9 Area name field — fixed at offset `0x503c` (NOT `0x5045`)

Reliable, structural, and trivial to read.

### 11.9.1 Format

Null-terminated ASCII. The string starts at offset `0x503c` (12 bytes
of preceding zeros), max length observed ~24 characters. Encoded as
`<chapter_prefix>_<location>`.

The earlier `diff_pair.py` code used `0x5045` (which truncates the
first 9 bytes — that's why GAMER1 read as just `"r"` and other saves
read as suffix fragments). The correct offset across all 102 saves is
`0x503c`. **Always verify by dumping `0x5030..0x5080` framing when in
doubt** — don't substitute chapter labels for what the bytes actually
say (lesson learned the hard way this session).

### 11.9.2 Observed area strings

| chapter prefix | location suffixes seen | game chapter (per user playthrough) |
|---|---|---|
| `sha_city_` | `port_2a`, `port_2a_int`, `sewer1a`, `lowerharvester` | Hengsha 2 |
| `sin_` | `omega_exterior` | Singapore — Omega Ranch (exterior) |
| `dlc_` | `hangar`, `cargo_int` | Missing Link DLC |
| `pic_` | `helipad` | Picus chapter |

(Chapter mapping above is from the user's playthrough; the file only
contains the prefix+location.)

### 11.9.3 Donor-area matching across the 102 saves

| target save | area | other saves in same area |
|---|---|---|
| GAMER5_4 | `sin_omega_exterior` | **GAMER6_4 (modhook fast-start, world-state-empty), GAMEA1_4** |
| GAMER23_4 | `dlc_hangar` | GAMER1_4, GAMER20_4, GAMER22_4, GAMER83_4 |
| GAMER25_4 / GAMER51_4 | `sha_city_port_2a` | GAMER53_4 |
| GAMER50_4 | `sha_city_lowerharvester` | (only one) |
| GAMER63_4 | `dlc_cargo_int` | GAMER24_4, GAMEA2_4, GAMEQ1_4 |

**GAMER6_4 matches GAMER5_4's area exactly** and is the only save in
the corpus with a verifiably scrubbed world state. This makes the
`GAMER5_prog + GAMER6_world` graft a much stronger experiment than the
prior `GAMER23 + GAMER63` attempt that failed in §11.1 — IF we are
willing to accept the inventory loss documented in §11.8.5.


## 11.10 Status going into next session

### 11.10.1 What we still want

Salvage GAMER23 / GAMER5 progression so the user does not replay the
Missing Link / Singapore chapters from scratch.

### 11.10.2 Honest tradeoff matrix

| Approach | Preserves XP/praxis? | Preserves inventory/ammo/augs? | Risk | Effort |
|---|---|---|---|---|
| Hook 16 only (preventive) | n/a (no repair) | n/a (no repair) | — | ~60 lines C; user replays current chapter |
| Surgical zero of just the `0x1fb000` band | Yes (header untouched) | Unknown — may or may not coincide with inventory bytes | Loader may still trip on remaining cross-refs | 30 min Python |
| `GAMER5_prog + GAMER6_world` hybrid (same area) | Yes | **No** (inventory is in world state, GAMER6 has none) | Low (just an experiment) | 10 min |
| RE the on-disk PC progression format via Ghidra (writer-side trace) | Yes | Yes (if successful) | Open-ended | multi-session |

### 11.10.3 Recommended sequence (next session)

1. **Surgical-zero experiment first** — fastest, most preserving.
   Replace bytes `0x1fb000..0x203800` of a corrupt save with zeros (or
   with GAMER51's bytes at the same offsets, since GAMER51 is in the
   same area). Write to a backup slot, attempt load. Outcome:
   - Loads cleanly → ship the tool.
   - Loads degraded → tells us inventory was in that band.
   - Crashes → loader has cross-refs we haven't accounted for.
2. **Hook 16 in parallel** — independent codepath, prevents new
   corruption regardless of repair outcome.
3. **`GAMER5_prog + GAMER6_world` graft** — last-resort fallback if
   user is willing to accept inventory loss.

### 11.10.4 Documentation discipline (lesson learned)

When reporting fields read from binary files, output **only** the
literal bytes (and raw hex for verification). Do not co-render with
chapter / level / feature labels unless they are independently
sourced. The session lost a question/answer cycle to me labeling
GAMER50 as "Missing Link" and GAMER23 as "sin_qrl_restricted_area"
when both labels were fabricated. The user knows their own playthrough;
my job is to read bytes faithfully.


## 11.11 Tools added this session

- `pythonSaveRepair/save_repair_tool.py`:
  - `--mode=scan` (Phase A1 v1) — stack/heap-range uint32 LE hit
    counter. Falsified. Kept for forensics.
  - `--mode=scan-anomalies` (Phase A1 v2) — byte-class signature
    detector (zero in [22,30] AND printable in [22,30]). Detects a
    real signature but it also fires on legitimate engine data; not a
    clean classifier by itself.
  - `--mode=read` — XP/praxis/inventory dump using form1.cs anchor
    patterns. Confirmed today that the Xbox 360 patterns do not match
    on PC; returns all-absent for PC saves.
- `pythonSaveRepair/decode_painkiller_count.py` — one-shot byte-diff
  between GAMER51 and GAMER25 outside known corrupt regions; output
  is the 5 progression-header diff ranges of §11.8.2.
- `pythonSaveRepair/evidence_check.py` — dumps the alleged corruption
  regions (raw bytes + byte-class) and the area-name field framing.
  Use it before relying on any prior claim in this document.

