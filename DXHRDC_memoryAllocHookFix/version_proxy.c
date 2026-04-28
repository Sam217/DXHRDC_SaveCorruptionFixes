/*
 * DXHR:DC Out-of-Memory Save Load Fix — version.dll proxy
 * =========================================================
 *
 * Drop version.dll next to DXHRDC.exe. It transparently forwards all
 * version-API calls to the real system version.dll while hooking the game's
 * custom MemHeapAllocator so large allocations that exhaust the internal
 * dlmalloc pool fall back to OS VirtualAlloc instead of crashing.
 *
 * FOUR HOOKS:
 *
 *   Hook 1 — GamePrintError  (RVA 0x001fbc60, __cdecl varargs)
 *     The original formats an error, calls HideGameWindowAndShowError,
 *     then ExceptionHandlerQ_terminate + int 3 — it NEVER returns.
 *     Our hook uses a flag to selectively suppress OOM errors (return
 *     normally) while letting non-OOM fatals still terminate.
 *
 *   Hook 2 — MemHeapAllocator::Allocate  (RVA 0x001fdcc0, __thiscall)
 *     Wraps the main allocator. Sets the suppress-OOM flag, calls orig,
 *     clears the flag.  If orig returns NULL → VirtualAlloc fallback.
 *
 *   Hook 3 — MemHeapAllocator::AllocateAligned (RVA 0x001fde30, __thiscall)
 *     Same pattern for the aligned allocation path.
 *     VirtualAlloc always returns page-aligned (4096), which satisfies
 *     any game alignment requirement (4, 8, 16, 64...).
 *
 *   Hook 4 — MemHeapAllocator::Free  (RVA 0x001fe010, __thiscall)
 *     If the pointer was allocated by our fallback → VirtualFree.
 *     Otherwise → call original dlmalloc free.
 *     Without this, passing a VirtualAlloc'd pointer to dlmalloc
 *     would corrupt the game's internal heap.
 *
 *   Hook 5 — InstanceTable::LoadFromStream  (RVA 0x000eceb0, __thiscall)
 *     ROOT CAUSE FIX.  Reads a count from the save stream and loops
 *     that many times restoring game instances.  Corrupted saves have
 *     huge counts causing runaway DynArray growth (128→256→512→1024 MB).
 *     Our hook caps the count to MAX_INSTANCES (50000) and fixes up
 *     the stream position to skip unprocessed entries.
 *
 *   Hook 6 — DynArray_PushBack_8bytes  (RVA 0x002b0dd0, __thiscall)
 *     UNIVERSAL SAFETY NET.  Called by 50+ functions for all DynArray
 *     growth.  When any caller has a runaway loop, this hook caps the
 *     array at MAX_DYNARRAY_ELEMENTS (100000) and logs the caller RVA.
 *
 * BUILD (VS2022 — open "x86 Native Tools Command Prompt for VS 2022"):
 *
 *   cl /LD /O2 /GS- version_proxy.c /Fe:version.dll ^
 *      /link /DEF:version.def /NODEFAULTLIB:libcmt.lib
 *
 *   Or just run:  build.bat
 *
 * INSTALL:
 *   Copy version.dll to your DXHRDC.exe directory.
 *   To uninstall, just delete it.
 *
 * DIAGNOSTICS:
 *   dxhr_memfix.log is created next to the exe with hook status,
 *   fallback allocations, and any suppressed errors.
 *
 *   For real-time console output, create an empty file called
 *   "dxhr_memfix_console" (no extension) next to DXHRDC.exe.
 *   A console window will appear alongside the game.
 *   Delete the file to disable.
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include "pch.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>
#include <windows.h>

/* ================================================================
 * 1. VERSION.DLL FORWARDING
 *
 * We load the REAL version.dll from System32 and forward all calls.
 * The .def file maps our export names to these stubs.
 * ================================================================ */

static HMODULE g_realVersion = NULL;

/* We use a uniform function-pointer type and cast at call sites
 * to keep the table compact.  Each stub has the correct signature. */

static FARPROC g_procs[17] = {0};

enum
{
	FN_GetFileVersionInfoA = 0,
	FN_GetFileVersionInfoW,
	FN_GetFileVersionInfoSizeA,
	FN_GetFileVersionInfoSizeW,
	FN_VerQueryValueA,
	FN_VerQueryValueW,
	FN_VerFindFileA,
	FN_VerFindFileW,
	FN_VerInstallFileA,
	FN_VerInstallFileW,
	FN_VerLanguageNameA,
	FN_VerLanguageNameW,
	FN_GetFileVersionInfoExA,
	FN_GetFileVersionInfoExW,
	FN_GetFileVersionInfoSizeExA,
	FN_GetFileVersionInfoSizeExW,
	FN_COUNT
};

static const char *g_procNames[FN_COUNT] = {
		"GetFileVersionInfoA",
		"GetFileVersionInfoW",
		"GetFileVersionInfoSizeA",
		"GetFileVersionInfoSizeW",
		"VerQueryValueA",
		"VerQueryValueW",
		"VerFindFileA",
		"VerFindFileW",
		"VerInstallFileA",
		"VerInstallFileW",
		"VerLanguageNameA",
		"VerLanguageNameW",
		"GetFileVersionInfoExA",
		"GetFileVersionInfoExW",
		"GetFileVersionInfoSizeExA",
		"GetFileVersionInfoSizeExW",
};

static void LoadRealVersionDLL(void)
{
	wchar_t path[MAX_PATH];
	GetSystemDirectoryW(path, MAX_PATH);
	lstrcatW(path, L"\\version.dll");
	g_realVersion = LoadLibraryW(path);
	if (!g_realVersion)
		return;
	/* GetProcAddress always uses ANSI names (by Windows design) */
	for (int i = 0; i < FN_COUNT; i++)
		g_procs[i] = GetProcAddress(g_realVersion, g_procNames[i]);
}

/* --- Forwarding stubs ---
 *
 * These are named EXACTLY like the real version.dll functions.
 * This works because we do NOT link against version.lib — we
 * load the real DLL manually via LoadLibrary/GetProcAddress.
 *
 * The .def file exports these names. The MSVC linker auto-strips
 * the __stdcall decoration (_Name@N) when exporting via .def,
 * producing clean undecorated exports that match what callers expect.
 *
 * IMPORTANT: No __declspec(dllexport) here! The .def file is the
 * sole export mechanism. Mixing both causes name decoration conflicts
 * on 32-bit MSVC where __stdcall adds _Name@N suffixes.
 */

typedef BOOL(WINAPI *t_GFVI)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL(WINAPI *t_GFVIW)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD(WINAPI *t_GFVIS)(LPCSTR, LPDWORD);
typedef DWORD(WINAPI *t_GFVISW)(LPCWSTR, LPDWORD);
typedef BOOL(WINAPI *t_VQV)(LPCVOID, LPCSTR, LPVOID *, PUINT);
typedef BOOL(WINAPI *t_VQVW)(LPCVOID, LPCWSTR, LPVOID *, PUINT);
typedef DWORD(WINAPI *t_VFF)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT);
typedef DWORD(WINAPI *t_VFFW)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
typedef DWORD(WINAPI *t_VIF)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT);
typedef DWORD(WINAPI *t_VIFW)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT);
typedef DWORD(WINAPI *t_VLN)(DWORD, LPSTR, DWORD);
typedef DWORD(WINAPI *t_VLNW)(DWORD, LPWSTR, DWORD);
typedef BOOL(WINAPI *t_GFVIX)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL(WINAPI *t_GFVIXW)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD(WINAPI *t_GFVISX)(DWORD, LPCSTR, LPDWORD);
typedef DWORD(WINAPI *t_GFVISXW)(DWORD, LPCWSTR, LPDWORD);

#define FWD(idx, type) ((type)g_procs[idx])

__declspec(dllexport) BOOL WINAPI fwd_GetFileVersionInfoA(LPCSTR a, DWORD b, DWORD c, LPVOID d) { return FWD(FN_GetFileVersionInfoA, t_GFVI) ? FWD(FN_GetFileVersionInfoA, t_GFVI)(a, b, c, d) : FALSE; }
__declspec(dllexport) BOOL WINAPI fwd_GetFileVersionInfoW(LPCWSTR a, DWORD b, DWORD c, LPVOID d) { return FWD(FN_GetFileVersionInfoW, t_GFVIW) ? FWD(FN_GetFileVersionInfoW, t_GFVIW)(a, b, c, d) : FALSE; }
__declspec(dllexport) DWORD WINAPI fwd_GetFileVersionInfoSizeA(LPCSTR a, LPDWORD b) { return FWD(FN_GetFileVersionInfoSizeA, t_GFVIS) ? FWD(FN_GetFileVersionInfoSizeA, t_GFVIS)(a, b) : 0; }
__declspec(dllexport) DWORD WINAPI fwd_GetFileVersionInfoSizeW(LPCWSTR a, LPDWORD b) { return FWD(FN_GetFileVersionInfoSizeW, t_GFVISW) ? FWD(FN_GetFileVersionInfoSizeW, t_GFVISW)(a, b) : 0; }
__declspec(dllexport) BOOL WINAPI fwd_VerQueryValueA(LPCVOID a, LPCSTR b, LPVOID *c, PUINT d) { return FWD(FN_VerQueryValueA, t_VQV) ? FWD(FN_VerQueryValueA, t_VQV)(a, b, c, d) : FALSE; }
__declspec(dllexport) BOOL WINAPI fwd_VerQueryValueW(LPCVOID a, LPCWSTR b, LPVOID *c, PUINT d) { return FWD(FN_VerQueryValueW, t_VQVW) ? FWD(FN_VerQueryValueW, t_VQVW)(a, b, c, d) : FALSE; }
__declspec(dllexport) DWORD WINAPI fwd_VerFindFileA(DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPSTR e, PUINT f, LPSTR g, PUINT h) { return FWD(FN_VerFindFileA, t_VFF) ? FWD(FN_VerFindFileA, t_VFF)(a, b, c, d, e, f, g, h) : 0; }
__declspec(dllexport) DWORD WINAPI fwd_VerFindFileW(DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPWSTR e, PUINT f, LPWSTR g, PUINT h) { return FWD(FN_VerFindFileW, t_VFFW) ? FWD(FN_VerFindFileW, t_VFFW)(a, b, c, d, e, f, g, h) : 0; }
__declspec(dllexport) DWORD WINAPI fwd_VerInstallFileA(DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPCSTR e, LPCSTR f, LPSTR g, PUINT h) { return FWD(FN_VerInstallFileA, t_VIF) ? FWD(FN_VerInstallFileA, t_VIF)(a, b, c, d, e, f, g, h) : 0; }
__declspec(dllexport) DWORD WINAPI fwd_VerInstallFileW(DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPCWSTR e, LPCWSTR f, LPWSTR g, PUINT h) { return FWD(FN_VerInstallFileW, t_VIFW) ? FWD(FN_VerInstallFileW, t_VIFW)(a, b, c, d, e, f, g, h) : 0; }
__declspec(dllexport) DWORD WINAPI fwd_VerLanguageNameA(DWORD a, LPSTR b, DWORD c) { return FWD(FN_VerLanguageNameA, t_VLN) ? FWD(FN_VerLanguageNameA, t_VLN)(a, b, c) : 0; }
__declspec(dllexport) DWORD WINAPI fwd_VerLanguageNameW(DWORD a, LPWSTR b, DWORD c) { return FWD(FN_VerLanguageNameW, t_VLNW) ? FWD(FN_VerLanguageNameW, t_VLNW)(a, b, c) : 0; }
__declspec(dllexport) BOOL WINAPI fwd_GetFileVersionInfoExA(DWORD a, LPCSTR b, DWORD c, DWORD d, LPVOID e) { return FWD(FN_GetFileVersionInfoExA, t_GFVIX) ? FWD(FN_GetFileVersionInfoExA, t_GFVIX)(a, b, c, d, e) : FALSE; }
__declspec(dllexport) BOOL WINAPI fwd_GetFileVersionInfoExW(DWORD a, LPCWSTR b, DWORD c, DWORD d, LPVOID e) { return FWD(FN_GetFileVersionInfoExW, t_GFVIXW) ? FWD(FN_GetFileVersionInfoExW, t_GFVIXW)(a, b, c, d, e) : FALSE; }
__declspec(dllexport) DWORD WINAPI fwd_GetFileVersionInfoSizeExA(DWORD a, LPCSTR b, LPDWORD c) { return FWD(FN_GetFileVersionInfoSizeExA, t_GFVISX) ? FWD(FN_GetFileVersionInfoSizeExA, t_GFVISX)(a, b, c) : 0; }
__declspec(dllexport) DWORD WINAPI fwd_GetFileVersionInfoSizeExW(DWORD a, LPCWSTR b, LPDWORD c) { return FWD(FN_GetFileVersionInfoSizeExW, t_GFVISXW) ? FWD(FN_GetFileVersionInfoSizeExW, t_GFVISXW)(a, b, c) : 0; }

/* ================================================================
 * 2. FALLBACK ALLOCATION TRACKING
 *
 * Every VirtualAlloc fallback is recorded here so that Free can
 * distinguish "ours" from "game's dlmalloc" pointers.
 * ================================================================ */

#define MAX_TRACKED 1024

typedef struct
{
	void *ptr;
	SIZE_T size;
} TrackedAlloc;

static TrackedAlloc g_tracked[MAX_TRACKED];
static volatile LONG g_trackedCount = 0;
static CRITICAL_SECTION g_trackCS;

static void TrackAdd(void *ptr, SIZE_T size)
{
	EnterCriticalSection(&g_trackCS);
	if (g_trackedCount < MAX_TRACKED)
	{
		g_tracked[g_trackedCount].ptr = ptr;
		g_tracked[g_trackedCount].size = size;
		g_trackedCount++;
	}
	LeaveCriticalSection(&g_trackCS);
}

static BOOL TrackRemove(void *ptr)
{
	BOOL found = FALSE;
	EnterCriticalSection(&g_trackCS);
	for (LONG i = 0; i < g_trackedCount; i++)
	{
		if (g_tracked[i].ptr == ptr)
		{
			g_tracked[i] = g_tracked[g_trackedCount - 1];
			g_trackedCount--;
			found = TRUE;
			break;
		}
	}
	LeaveCriticalSection(&g_trackCS);
	return found;
}

/* ================================================================
 * 3. LOG FILE
 * ================================================================ */

static HANDLE g_logFile = INVALID_HANDLE_VALUE;
static BOOL g_console = FALSE; /* TRUE = also log to console */

static void LogInit(void)
{
	g_logFile = CreateFileA("dxhr_memfix.log",
													GENERIC_WRITE, FILE_SHARE_READ,
													NULL, CREATE_ALWAYS,
													FILE_ATTRIBUTE_NORMAL, NULL);

	/* Console mode: create a console window if a trigger file exists.
	 * Place an empty file called "dxhr_memfix_console" (no extension)
	 * next to DXHRDC.exe to enable it.  Delete the file to disable.
	 * This avoids recompilation and has zero overhead when disabled. */
	DWORD attr = GetFileAttributesA("dxhr_memfix_console");
	if (attr != INVALID_FILE_ATTRIBUTES)
	{
		if (AllocConsole())
		{
			/* Redirect stdout to the new console */
			FILE *dummy;
			freopen_s(&dummy, "CONOUT$", "w", stdout);
			SetConsoleTitleA("DXHR Memory Fix — Debug Console");
			g_console = TRUE;
		}
	}
}

static void Log(const char *fmt, ...)
{
	char buf[2048];
	va_list ap;
	va_start(ap, fmt);
	int n = _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
	va_end(ap);
	if (n <= 0)
		return;
	buf[n] = 0;

	/* Write to log file */
	if (g_logFile != INVALID_HANDLE_VALUE)
	{
		DWORD written;
		WriteFile(g_logFile, buf, (DWORD)n, &written, NULL);
		FlushFileBuffers(g_logFile);
	}

	/* Write to console (if enabled) */
	if (g_console)
	{
		printf("%s", buf);
	}
}

/* ================================================================
 * 3b. CONFIGURATION
 * ================================================================ */

/* Allocations larger than this threshold will have their call stack
 * traced so we can identify the caller.  64 MB filters out normal
 * game allocations but catches the pathological ones. */
#define LARGE_ALLOC_THRESHOLD (64 * 1024 * 1024)

/* Allocations larger than this are rejected outright (NULL returned).
 * This prevents runaway geometric growth (256→512→1024→2048→...) from
 * wasting address space.  Set to 0 to disable the cap.
 * 768 MB fits comfortably in a 32-bit process alongside everything else. */
#define MAX_SANE_ALLOC_SIZE (768 * 1024 * 1024)

/* ================================================================
 * 3c. STACK TRACE CAPTURE
 *
 * CaptureStackBackTrace is exported from ntdll and doesn't require
 * DbgHelp.  We log return addresses as EXE-relative RVAs so they
 * can be looked up directly in Ghidra.
 * ================================================================ */

#define MAX_STACK_FRAMES 12

/* Resolve an address to its containing module name + offset */
static void GetModuleForAddress(DWORD addr, char *outBuf, int bufSize)
{
	HMODULE hMod = NULL;
	if (GetModuleHandleExW(
					GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
							GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
					(LPCWSTR)(DWORD_PTR)addr, &hMod))
	{
		wchar_t modPath[MAX_PATH];
		if (GetModuleFileNameW(hMod, modPath, MAX_PATH))
		{
			/* Extract just the filename from the full path */
			const wchar_t *name = modPath;
			const wchar_t *p = modPath;
			while (*p)
			{
				if (*p == L'\\' || *p == L'/')
					name = p + 1;
				p++;
			}
			DWORD offset = addr - (DWORD)(DWORD_PTR)hMod;
			_snprintf_s(outBuf, bufSize, _TRUNCATE, "%ls+0x%X", name, offset);
			return;
		}
	}
	_snprintf_s(outBuf, bufSize, _TRUNCATE, "unknown");
}

static void LogStackTrace(int skipFrames)
{
	void *frames[MAX_STACK_FRAMES];
	USHORT captured = CaptureStackBackTrace((ULONG)skipFrames,
																					MAX_STACK_FRAMES,
																					frames, NULL);
	BYTE *base = (BYTE *)GetModuleHandleA(NULL);
	DWORD baseAddr = (DWORD)(DWORD_PTR)base;
	/* Approximate .text range: assume 32 MB max EXE code for bounds check */
	DWORD exeMax = baseAddr + 0x02000000;

	Log("[MEMFIX]   Stack trace (lookup RVAs in Ghidra):\r\n");
	for (USHORT i = 0; i < captured; i++)
	{
		DWORD addr = (DWORD)(DWORD_PTR)frames[i];
		if (addr >= baseAddr && addr < exeMax)
		{
			Log("[MEMFIX]     #%u: 0x%08X  (EXE RVA 0x%08X)\r\n",
					(unsigned)i, addr, addr - baseAddr);
		} else
		{
			char modInfo[256];
			GetModuleForAddress(addr, modInfo, sizeof(modInfo));
			Log("[MEMFIX]     #%u: 0x%08X  (%s)\r\n",
					(unsigned)i, addr, modInfo);
		}
	}
}
}

/* ================================================================
 * 4. INLINE HOOK ENGINE  (32-bit x86 only)
 *
 * Overwrites the first `stealN` bytes (which MUST be complete
 * instructions) with a JMP rel32 to our detour.  The stolen bytes
 * are copied to an executable trampoline followed by a JMP back
 * to original+stealN.
 *
 * The log output dumps the first 16 bytes of each target so you
 * can visually verify the prologue matches what Ghidra shows.
 * ================================================================ */

typedef struct
{
	void *trampoline; /* executable: stolen bytes + JMP back */
} HookCtx;

static HookCtx g_hkError;	 /* GamePrintError            */
static HookCtx g_hkAlloc;	 /* MemHeapAllocator::Allocate */
static HookCtx g_hkAllocA; /* MemHeapAllocator::AllocateAligned */
static HookCtx g_hkFree;	 /* MemHeapAllocator::Free     */

static BOOL InstallHook(HookCtx *ctx, void *target, void *detour, int stealN)
{
	/* Allocate RWX trampoline */
	BYTE *tramp = (BYTE *)VirtualAlloc(NULL, 64,
																		 MEM_COMMIT | MEM_RESERVE,
																		 PAGE_EXECUTE_READWRITE);
	if (!tramp)
		return FALSE;

	/* Copy stolen bytes to trampoline */
	memcpy(tramp, target, stealN);

	/* Append: JMP (target + stealN) */
	tramp[stealN] = 0xE9;
	*(DWORD *)(tramp + stealN + 1) =
			(DWORD)((BYTE *)target + stealN) - (DWORD)(tramp + stealN + 5);

	ctx->trampoline = (void *)tramp;

	/* Overwrite target prologue with: JMP detour */
	DWORD oldProt;
	VirtualProtect(target, stealN, PAGE_EXECUTE_READWRITE, &oldProt);
	BYTE *t = (BYTE *)target;
	t[0] = 0xE9; /* JMP rel32 */
	*(DWORD *)(t + 1) = (DWORD)detour - (DWORD)(t + 5);
	/* NOP-pad any remaining stolen bytes beyond the 5-byte JMP */
	for (int i = 5; i < stealN; i++)
		t[i] = 0x90;
	VirtualProtect(target, stealN, oldProt, &oldProt);
	FlushInstructionCache(GetCurrentProcess(), target, stealN);

	return TRUE;
}

/* ================================================================
 * 5. OOM SUPPRESSION FLAG
 *
 * Set to TRUE around calls to the original allocator so that
 * Hook_GamePrintError knows to suppress the crash and return.
 * Only OOM errors get suppressed; other fatals still terminate.
 * ================================================================ */

/* Per-thread would be ideal, but a simple volatile global is fine
 * for this game since the allocator wrappers serialize with a
 * CriticalSection anyway (see FUN_001fe310/FUN_001fe350). */
static volatile BOOL g_suppressOOM = FALSE;

/* ================================================================
 * 6. HOOK 1 — GamePrintError
 *
 * RVA 0x001fbc60   __cdecl   void (const char* fmt, ...)
 *
 * Prologue (8 bytes stolen):
 *   001fbc60  8B 4C 24 04   MOV ECX,[ESP+4]
 *   001fbc64  8D 44 24 08   LEA EAX,[ESP+8]
 *
 * Original body: vsnprintf → MessageBox → terminate → int 3
 * ================================================================ */

#define RVA_GAMEPRINTEERROR 0x001fbc60
#define STEAL_ERROR 8

typedef void(__cdecl *OrigGamePrintError_t)(const char *fmt, ...);

static void __cdecl Hook_GamePrintError(const char *fmt, ...)
{
	/* Format the message (same as original would) */
	char buf[1024];
	va_list ap;
	va_start(ap, fmt);
	_vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
	va_end(ap);

	if (g_suppressOOM)
	{
		/* We're inside Hook_Allocate → suppress crash, just log */
		Log("[MEMFIX] *** OOM SUPPRESSED *** %s\r\n", buf);
		return; /* <-- KEY: return instead of terminating */
	}

	/* Non-OOM fatal error — replicate original behavior:
	 * show the error and terminate.  We can't forward varargs
	 * through the trampoline, so we do it directly. */
	Log("[MEMFIX] FATAL (not OOM): %s\r\n", buf);
	MessageBoxA(NULL, buf, "DXHR:DC Fatal Error", MB_OK | MB_ICONERROR);
	ExitProcess(1);
}

/* ================================================================
 * 7. HOOK 2 — MemHeapAllocator::Allocate
 *
 * RVA 0x001fdcc0   __thiscall   int (int size, int category)
 *
 * Prologue (6 bytes stolen):
 *   001fdcc0  55              PUSH EBP
 *   001fdcc1  8B EC           MOV EBP,ESP
 *   001fdcc3  83 E4 C0        AND ESP,0xFFFFFFC0
 *
 * Returns via RET 8 (callee cleans 2 stack args).
 *
 * We capture __thiscall as __fastcall:
 *   ECX=this, EDX=unused, stack=[size, category]
 * ================================================================ */

#define RVA_ALLOC 0x001fdcc0
#define STEAL_ALLOC 6

typedef int(__fastcall *OrigAlloc_t)(void *, void *, int, int);

static int __fastcall Hook_Allocate(void *this_, void *edx_,
																		int size, int category)
{
	/* ── Sanity cap: reject insane allocations ── */
	if (size < 0 || (MAX_SANE_ALLOC_SIZE > 0 &&
									 (unsigned)size > MAX_SANE_ALLOC_SIZE))
	{
		Log("[MEMFIX] *** REJECTED insane Allocate(%d, cat=%d) "
				"[size=0x%X, signed=%d] ***\r\n",
				size, category, (unsigned)size, size);
		LogStackTrace(1);
		return 0; /* game sees NULL, must handle it */
	}

	/* ── Log large allocations with stack trace ── */
	if ((unsigned)size > LARGE_ALLOC_THRESHOLD)
	{
		Log("[MEMFIX] LARGE Allocate(%u = %.1f MB, cat=%d) requested\r\n",
				(unsigned)size, (double)size / (1024 * 1024), category);
		LogStackTrace(1);
	}

	/* ── Call original with OOM suppression ── */
	g_suppressOOM = TRUE;
	OrigAlloc_t orig = (OrigAlloc_t)(g_hkAlloc.trampoline);
	int result = orig(this_, edx_, size, category);
	g_suppressOOM = FALSE;

	if (result == 0 && size > 0)
	{
		/* Game's internal dlmalloc pool exhausted → OS fallback */
		void *fb = VirtualAlloc(NULL, (SIZE_T)(unsigned int)size,
														MEM_COMMIT | MEM_RESERVE,
														PAGE_READWRITE);
		if (fb)
		{
			TrackAdd(fb, (SIZE_T)(unsigned int)size);
			result = (int)(DWORD_PTR)fb;
			Log("[MEMFIX] FALLBACK: Allocate(%u, cat=%d) -> 0x%08X\r\n",
					(unsigned)size, category, result);
		} else
		{
			Log("[MEMFIX] FALLBACK FAILED: Allocate(%u) err=%u\r\n",
					(unsigned)size, GetLastError());
		}
	}
	return result;
}

/* ================================================================
 * 8. HOOK 3 — MemHeapAllocator::AllocateAligned
 *
 * RVA 0x001fde30   __thiscall   int (int align, int size, int category)
 *
 * Prologue (6 bytes stolen) — identical to Allocate:
 *   001fde30  55              PUSH EBP
 *   001fde31  8B EC           MOV EBP,ESP
 *   001fde33  83 E4 C0        AND ESP,0xFFFFFFC0
 *
 * Returns via RET 0xC (callee cleans 3 stack args).
 *
 * __fastcall capture:
 *   ECX=this, EDX=unused, stack=[align, size, category]
 * ================================================================ */

#define RVA_ALLOCA 0x001fde30
#define STEAL_ALLOCA 6

typedef int(__fastcall *OrigAllocA_t)(void *, void *, int, int, int);

static int __fastcall Hook_AllocateAligned(void *this_, void *edx_,
																					 int align, int size, int category)
{
	/* ── Sanity cap ── */
	if (size < 0 || (MAX_SANE_ALLOC_SIZE > 0 &&
									 (unsigned)size > MAX_SANE_ALLOC_SIZE))
	{
		Log("[MEMFIX] *** REJECTED insane AllocAligned(%d, align=%d, cat=%d) ***\r\n",
				size, align, category);
		LogStackTrace(1);
		return 0;
	}

	/* ── Log large allocations with stack trace ── */
	if ((unsigned)size > LARGE_ALLOC_THRESHOLD)
	{
		Log("[MEMFIX] LARGE AllocAligned(%u = %.1f MB, align=%d, cat=%d) requested\r\n",
				(unsigned)size, (double)size / (1024 * 1024), align, category);
		LogStackTrace(1);
	}

	g_suppressOOM = TRUE;
	OrigAllocA_t orig = (OrigAllocA_t)(g_hkAllocA.trampoline);
	int result = orig(this_, edx_, align, size, category);
	g_suppressOOM = FALSE;

	if (result == 0 && size > 0)
	{
		/* VirtualAlloc is page-aligned (4096) — satisfies any
		 * game alignment (4, 8, 16, 64, 128...) */
		void *fb = VirtualAlloc(NULL, (SIZE_T)(unsigned int)size,
														MEM_COMMIT | MEM_RESERVE,
														PAGE_READWRITE);
		if (fb)
		{
			TrackAdd(fb, (SIZE_T)(unsigned int)size);
			result = (int)(DWORD_PTR)fb;
			Log("[MEMFIX] FALLBACK: AllocAligned(%u, align=%d, cat=%d) -> 0x%08X\r\n",
					(unsigned)size, align, category, result);
		} else
		{
			Log("[MEMFIX] FALLBACK FAILED: AllocAligned(%u) err=%u\r\n",
					(unsigned)size, GetLastError());
		}
	}
	return result;
}

/* ================================================================
 * 9. HOOK 4 — MemHeapAllocator::Free
 *
 * RVA 0x001fe010   __thiscall   void (int ptr)
 *
 * Prologue (6 bytes stolen):
 *   001fe010  56              PUSH ESI
 *   001fe011  57              PUSH EDI
 *   001fe012  8B 7C 24 0C    MOV EDI,[ESP+0xC]
 *
 * Returns via RET 4 (callee cleans 1 stack arg).
 *
 * The original checks pointer ownership before calling dlmalloc
 * free.  If we let a VirtualAlloc'd pointer reach dlmalloc, it
 * would corrupt the heap → hence this hook is critical.
 * ================================================================ */

#define RVA_FREE 0x001fe010
#define STEAL_FREE 6

typedef void(__fastcall *OrigFree_t)(void *, void *, int);

static void __fastcall Hook_Free(void *this_, void *edx_, int ptr)
{
	if (ptr != 0 && TrackRemove((void *)(DWORD_PTR)ptr))
	{
		/* This pointer came from our VirtualAlloc fallback */
		VirtualFree((void *)(DWORD_PTR)ptr, 0, MEM_RELEASE);
		Log("[MEMFIX] VirtualFree(0x%08X)\r\n", ptr);
		return;
	}
	/* Not ours → delegate to original dlmalloc free */
	OrigFree_t orig = (OrigFree_t)(g_hkFree.trampoline);
	orig(this_, edx_, ptr);
}

/* ================================================================
 * 9b. HOOK 5 — InstanceTable::LoadFromStream (instance count cap)
 *
 * RVA 0x000eceb0   __thiscall   void (uint* stream)
 *
 * This function reads a count from the save stream and loops that
 * many times, restoring game object instances and pushing them into
 * a DynArray.  When the save file is corrupted, the count can be
 * millions or billions, causing runaway geometric DynArray growth
 * (128→256→512→1024 MB) until OOM.
 *
 * Prologue (5 bytes stolen):
 *   000eceb0  83 EC 08      SUB ESP, 0x8
 *   000eceb3  53            PUSH EBX
 *   000eceb4  56            PUSH ESI
 *
 * Stream layout:
 *   stream[0] = bytes consumed (uint)
 *   stream[1] = total bytes available (uint)
 *   stream[2] = current read pointer (BYTE*)
 *
 * Data at read pointer: [1-byte flag] [4-byte count] [count × 4-byte indices]
 *
 * Our hook peeks at the count, caps it if insane, patches the stream
 * data in-place, calls the original, then fixes up the stream position
 * to skip the entries we discarded.
 * ================================================================ */

#define RVA_LOADSTREAM 0x000eceb0
#define STEAL_LOADSTREAM 5

/* Maximum number of instances to restore from a save file.
 * Normal gameplay: hundreds at most.
 * 50000 is extremely generous while preventing runaway loops. */
#define MAX_INSTANCES 50000

static HookCtx g_hkLoadStream;

typedef void(__fastcall *OrigLoadStream_t)(void *, void *, unsigned int *);

static void __fastcall Hook_LoadFromStream(void *this_, void *edx_,
																					 unsigned int *stream)
{
	/* Stream: [0]=consumed, [1]=total, [2]=read_ptr */
	unsigned int pos = stream[0];
	unsigned int total = stream[1];
	BYTE *dataPtr = (BYTE *)stream[2];

	/* The function reads 1 byte (flag) then 4 bytes (count).
	 * Peek at the count without advancing the stream. */
	unsigned int original_count = 0;
	BOOL capped = FALSE;

	if (pos + 5 <= total)
	{
		/* Count is at dataPtr + 1 (after the 1-byte flag) */
		unsigned int count;
		memcpy(&count, dataPtr + 1, 4); /* safe unaligned read */

		if (count > MAX_INSTANCES)
		{
			original_count = count;
			capped = TRUE;

			Log("[MEMFIX] *** SAVE CORRUPTION DETECTED ***\r\n");
			Log("[MEMFIX]   InstanceTable::LoadFromStream count = %u"
					" (expected < %u)\r\n",
					count, MAX_INSTANCES);
			Log("[MEMFIX]   Capping to %u to prevent runaway allocation\r\n",
					MAX_INSTANCES);

			/* Patch the count in-place in the stream buffer */
			unsigned int capped_val = MAX_INSTANCES;
			memcpy(dataPtr + 1, &capped_val, 4);
		}
	}

	/* Call original function (reads the now-capped count) */
	OrigLoadStream_t orig = (OrigLoadStream_t)(g_hkLoadStream.trampoline);
	orig(this_, edx_, stream);

	/* Fix up stream position: skip the entries we didn't process.
	 * Each entry is 4 bytes (a uint instance index).
	 * The original only read MAX_INSTANCES entries; we need to
	 * advance past the remaining (original_count - MAX_INSTANCES) entries. */
	if (capped && original_count > MAX_INSTANCES)
	{
		unsigned int skipped_entries = original_count - MAX_INSTANCES;
		unsigned int skip_bytes = skipped_entries * 4;

		/* Don't advance past end of stream */
		unsigned int remaining = total - stream[0];
		if (skip_bytes > remaining)
		{
			Log("[MEMFIX]   Stream too short to skip all entries,"
					" advancing to end (remaining=%u, need=%u)\r\n",
					remaining, skip_bytes);
			skip_bytes = remaining;
		}

		stream[0] += skip_bytes;
		stream[2] = (unsigned int)((BYTE *)stream[2] + skip_bytes);

		Log("[MEMFIX]   Stream position fixed: skipped %u bytes"
				" (%u discarded entries)\r\n",
				skip_bytes, skipped_entries);

		/* Restore original count in stream data so we don't leave
		 * a modified save buffer (even though it's a temp buffer) */
		BYTE *count_location = dataPtr + 1;
		/* Only restore if the pointer is still within stream bounds */
		if ((unsigned int)(count_location - (BYTE *)0) < 0xFFFF0000)
		{
			memcpy(count_location, &original_count, 4);
		}
	}
}

/* ================================================================
 * 9c. HOOK 6 — DynArray_PushBack_8bytes (universal growth cap)
 *
 * RVA 0x002b0dd0   __thiscall   void (undefined4* element)
 *
 * This is the GENERIC fix.  Called by 50+ functions throughout the
 * game for all DynArray<8-byte-element> growth.  When any caller
 * has a runaway loop (corrupted save count, etc.), this hook
 * prevents the DynArray from growing beyond MAX_DYNARRAY_ELEMENTS.
 *
 * Prologue (5 bytes stolen):
 *   002b0dd0  56            PUSH ESI
 *   002b0dd1  8B F1         MOV ESI, ECX
 *   002b0dd3  8B 0E         MOV ECX, [ESI]
 *
 * DynArray layout (this pointer):
 *   this[0] = count     (current number of elements)
 *   this[1] = capacity  (allocated slots)
 *   this[2] = buffer    (pointer to element data)
 *
 * Returns void.  RET 0x4 (callee cleans 1 stack arg).
 * ================================================================ */

#define RVA_PUSHBACK 0x002b0dd0
#define STEAL_PUSHBACK 5

/* Max elements before we refuse to grow.
 * At 8 bytes/element: 100000 = 800 KB — more than any normal array.
 * The corrupted path tries to grow to 128 million entries. */
#define MAX_DYNARRAY_ELEMENTS 100000

static HookCtx g_hkPushBack;
static volatile LONG g_pushbackWarnings = 0; /* throttle logging */

typedef void(__fastcall *OrigPushBack_t)(void *, void *, void *);

static void __fastcall Hook_DynArrayPushBack(void *this_, void *edx_,
																						 void *element)
{
	unsigned int *arr = (unsigned int *)this_;
	unsigned int count = arr[0];

	if (count >= MAX_DYNARRAY_ELEMENTS)
	{
		/* Runaway growth detected — refuse the push.
		 * Log the first few occurrences with caller address. */
		LONG warned = InterlockedIncrement(&g_pushbackWarnings);
		if (warned <= 5)
		{
			void *caller = NULL;
			CaptureStackBackTrace(1, 1, &caller, NULL);

			BYTE *base = (BYTE *)GetModuleHandleA(NULL);
			DWORD callerAddr = (DWORD)(DWORD_PTR)caller;
			DWORD baseAddr = (DWORD)(DWORD_PTR)base;

			Log("[MEMFIX] *** DynArray GROWTH BLOCKED ***\r\n");
			Log("[MEMFIX]   count=%u (max=%u), capacity=%u\r\n",
					count, MAX_DYNARRAY_ELEMENTS, arr[1]);
			Log("[MEMFIX]   caller: 0x%08X (EXE RVA 0x%08X)\r\n",
					callerAddr, callerAddr - baseAddr);

			if (warned == 5)
			{
				Log("[MEMFIX]   (further DynArray warnings suppressed)\r\n");
			}
		}
		/* Skip the push — return without modifying the array.
		 * The caller's loop continues but the array doesn't grow,
		 * so no more allocations are triggered. */
		return;
	}

	/* Normal case — delegate to original PushBack */
	OrigPushBack_t orig = (OrigPushBack_t)(g_hkPushBack.trampoline);
	orig(this_, edx_, element);
}

/* ================================================================
 * 9d. HOOK 7 — DynArray4_PushBack (4-byte element variant)
 *
 * RVA 0x0014ec40   __thiscall   void (undefined4* element)
 *
 * CONFIRMED crash source: Hud::LoadActiveGroups reads from a
 * corrupted save stream in a while-loop until it hits a 0 terminator.
 * If the terminator is missing, it loops millions of times, pushing
 * into this DynArray via DynArray4_PushBack (4 bytes per element).
 *
 * Same doubling pattern as DynArray_PushBack_8bytes, but allocates
 * new_capacity * 4 instead of * 8.
 *
 * DynArray layout: this[0]=count, this[1]=capacity, this[2]=buffer
 *
 * Prologue (5 bytes stolen):
 *   0014ec40  56            PUSH ESI
 *   0014ec41  8B F1         MOV ESI, ECX
 *   0014ec43  8B 0E         MOV ECX, [ESI]
 *
 * Returns via RET 0x4 (callee cleans 1 stack arg).
 * ================================================================ */

#define RVA_PUSHBACK4 0x0014ec40
#define STEAL_PUSHBACK4 5

static HookCtx g_hkPushBack4;
static volatile LONG g_pushback4Warnings = 0;

typedef void(__fastcall *OrigPushBack4_t)(void *, void *, void *);

static void __fastcall Hook_DynArray4PushBack(void *this_, void *edx_,
																							void *element)
{
	unsigned int *arr = (unsigned int *)this_;
	unsigned int count = arr[0];

	if (count >= MAX_DYNARRAY_ELEMENTS)
	{
		LONG warned = InterlockedIncrement(&g_pushback4Warnings);
		if (warned <= 5)
		{
			void *caller = NULL;
			CaptureStackBackTrace(1, 1, &caller, NULL);

			BYTE *base = (BYTE *)GetModuleHandleA(NULL);
			DWORD callerAddr = (DWORD)(DWORD_PTR)caller;
			DWORD baseAddr = (DWORD)(DWORD_PTR)base;

			Log("[MEMFIX] *** DynArray4 GROWTH BLOCKED ***\r\n");
			Log("[MEMFIX]   count=%u (max=%u), capacity=%u\r\n",
					count, MAX_DYNARRAY_ELEMENTS, arr[1]);
			Log("[MEMFIX]   caller: 0x%08X (EXE RVA 0x%08X)\r\n",
					callerAddr, callerAddr - baseAddr);

			if (warned == 5)
			{
				Log("[MEMFIX]   (further DynArray4 warnings suppressed)\r\n");
			}
		}
		return; /* refuse the push */
	}

	OrigPushBack4_t orig = (OrigPushBack4_t)(g_hkPushBack4.trampoline);
	orig(this_, edx_, element);
}

/* ================================================================
 * 10. HOOK INSTALLATION
 * ================================================================ */

static void LogBytes(const char *label, BYTE *addr, int n)
{
	char line[256];
	int pos = sprintf_s(line, sizeof(line), "[MEMFIX] %s 0x%08X:",
											label, (unsigned)(DWORD_PTR)addr);
	for (int i = 0; i < n && i < 16; i++)
		pos += sprintf_s(line + pos, sizeof(line) - pos, " %02X", addr[i]);
	strcat_s(line, sizeof(line), "\r\n");
	Log("%s", line);
}

/* ================================================================
 * 10b. VECTORED EXCEPTION HANDLER — CRASH DIAGNOSTIC
 *
 * Logs access violations and other structured exceptions with the
 * exception address as an EXE RVA (for Ghidra lookup) and the
 * offending memory address.
 *
 * We DO NOT handle the exception — we let it propagate so the
 * normal crash dialog still appears.  We just add logging.
 * ================================================================ */

static volatile LONG g_exceptionLogged = 0; /* log only once */

static LONG NTAPI Veh_CrashLogger(PEXCEPTION_POINTERS info)
{
	DWORD code = info->ExceptionRecord->ExceptionCode;

	/* Only log "real" crashes — skip C++ exceptions, debug breaks, etc. */
	if (code != EXCEPTION_ACCESS_VIOLATION &&
			code != EXCEPTION_ILLEGAL_INSTRUCTION &&
			code != EXCEPTION_STACK_OVERFLOW &&
			code != EXCEPTION_PRIV_INSTRUCTION)
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}

	/* Log only the first exception — prevents infinite spam when
	 * the exception re-fires because no handler resolved it. */
	if (InterlockedCompareExchange(&g_exceptionLogged, 1, 0) != 0)
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}

	BYTE *base = (BYTE *)GetModuleHandleA(NULL);
	DWORD exAddr = (DWORD)(DWORD_PTR)info->ExceptionRecord->ExceptionAddress;
	DWORD baseAddr = (DWORD)(DWORD_PTR)base;

	Log("[MEMFIX] ============ EXCEPTION ============\r\n");
	Log("[MEMFIX] Code:     0x%08X\r\n", code);
	Log("[MEMFIX] Address:  0x%08X  (EXE RVA 0x%08X)\r\n",
			exAddr, exAddr - baseAddr);

	if (code == EXCEPTION_ACCESS_VIOLATION)
	{
		ULONG_PTR *params = info->ExceptionRecord->ExceptionInformation;
		const char *op = (params[0] == 0) ? "READ" : (params[0] == 1) ? "WRITE"
																						 : (params[0] == 8)		? "EXEC"
																																	: "?";
		Log("[MEMFIX] Op:       %s at 0x%08X\r\n",
				op, (unsigned)params[1]);
	}

	/* Register dump (most useful ones) */
	CONTEXT *ctx = info->ContextRecord;
	Log("[MEMFIX] EAX=%08X EBX=%08X ECX=%08X EDX=%08X\r\n",
			(unsigned)ctx->Eax, (unsigned)ctx->Ebx,
			(unsigned)ctx->Ecx, (unsigned)ctx->Edx);
	Log("[MEMFIX] ESI=%08X EDI=%08X EBP=%08X ESP=%08X\r\n",
			(unsigned)ctx->Esi, (unsigned)ctx->Edi,
			(unsigned)ctx->Ebp, (unsigned)ctx->Esp);

	/* Walk the REAL crash stack by scanning ESP for return addresses.
	 * EBP chain walking fails here because many game functions
	 * (compiled with /O2 + FPO) don't use EBP as a frame pointer.
	 * Instead, we scan upward from ESP looking for values that
	 * look like code addresses within the EXE's .text section.
	 * This is the same heuristic VS debugger uses. */
	Log("[MEMFIX] Crash call stack (stack scan):\r\n");
	{
		DWORD eip = (DWORD)(DWORD_PTR)info->ExceptionRecord->ExceptionAddress;
		DWORD esp = ctx->Esp;
		DWORD exeStart = baseAddr;
		DWORD exeEnd = baseAddr + 0x0067F000; /* approx .text end */

		/* Frame 0: the crash site itself */
		Log("[MEMFIX]   #0: 0x%08X  (EXE RVA 0x%08X)  *** CRASH ***\r\n",
				eip, eip - baseAddr);

		/* Scan stack for return addresses.
		 * A return address is a DWORD on the stack that points into
		 * the EXE's .text section. Not all matches are real frames
		 * (some may be old/stale values), but it's the best we can
		 * do without symbols or .pdata. */
		int found = 0;
		for (DWORD scan = esp; scan < esp + 0x400 && found < 20; scan += 4)
		{
			if (IsBadReadPtr((void *)scan, 4))
				break;

			DWORD val = *(DWORD *)scan;
			if (val > exeStart && val < exeEnd)
			{
				/* Verify: the byte before this address should be a
				 * CALL instruction (E8 or FF). This reduces false
				 * positives from stale stack data. */
				if (!IsBadReadPtr((void *)(val - 5), 5))
				{
					BYTE prev = *(BYTE *)(val - 5);	 /* E8 = CALL rel32 */
					BYTE prev2 = *(BYTE *)(val - 2); /* FF xx = CALL reg/mem */
					BYTE prev6 = *(BYTE *)(val - 6); /* FF xx = CALL [reg+disp8] */
					if (prev == 0xE8 || prev2 == 0xFF || prev6 == 0xFF)
					{
						found++;
						Log("[MEMFIX]   #%d: 0x%08X  (EXE RVA 0x%08X)\r\n",
								found, val, val - baseAddr);
					}
				}
			}
		}

		if (found == 0)
		{
			Log("[MEMFIX]   (no return addresses found on stack)\r\n");
		}
	}
	Log("[MEMFIX] ====================================\r\n");

	/* Let the exception continue (don't swallow it) */
	return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL InstallAllHooks(void)
{
	BYTE *base = (BYTE *)GetModuleHandleA(NULL);
	if (!base)
	{
		Log("[MEMFIX] ERROR: GetModuleHandle(NULL) failed\r\n");
		return FALSE;
	}
	Log("[MEMFIX] EXE base = 0x%08X\r\n", (unsigned)(DWORD_PTR)base);

	BYTE *pError = base + RVA_GAMEPRINTEERROR;
	BYTE *pAlloc = base + RVA_ALLOC;
	BYTE *pAllocA = base + RVA_ALLOCA;
	BYTE *pFree = base + RVA_FREE;

	/* Dump first 16 bytes of each target — compare against Ghidra
	 * to verify we're patching the right place. */
	LogBytes("GamePrintError ", pError, 16);
	LogBytes("Allocate       ", pAlloc, 16);
	LogBytes("AllocateAligned", pAllocA, 16);
	LogBytes("Free           ", pFree, 16);

	/* Expected prologues (from Ghidra disassembly):
	 *   GamePrintError:  8B 4C 24 04  8D 44 24 08  50 ...
	 *   Allocate:        55 8B EC  83 E4 C0  83 EC 34 ...
	 *   AllocateAligned: 55 8B EC  83 E4 C0  83 EC 34 ...
	 *   Free:            56 57  8B 7C 24 0C  8B F1 ...
	 */

	/* Verify first bytes match expected prologue */
	BOOL mismatch = FALSE;

	if (pError[0] != 0x8B || pError[1] != 0x4C)
	{
		Log("[MEMFIX] WARNING: GamePrintError prologue mismatch! "
				"Expected 8B 4C, got %02X %02X\r\n",
				pError[0], pError[1]);
		mismatch = TRUE;
	}
	if (pAlloc[0] != 0x55 || pAlloc[1] != 0x8B || pAlloc[2] != 0xEC)
	{
		Log("[MEMFIX] WARNING: Allocate prologue mismatch! "
				"Expected 55 8B EC, got %02X %02X %02X\r\n",
				pAlloc[0], pAlloc[1], pAlloc[2]);
		mismatch = TRUE;
	}
	if (pFree[0] != 0x56 || pFree[1] != 0x57)
	{
		Log("[MEMFIX] WARNING: Free prologue mismatch! "
				"Expected 56 57, got %02X %02X\r\n",
				pFree[0], pFree[1]);
		mismatch = TRUE;
	}

	if (mismatch)
	{
		Log("[MEMFIX] *** ABORTING — prologue mismatch. "
				"Wrong binary version? Check log for details. ***\r\n");
		return FALSE;
	}

	/* Hook 1: GamePrintError — suppress OOM crash */
	if (!InstallHook(&g_hkError, pError, Hook_GamePrintError, STEAL_ERROR))
	{
		Log("[MEMFIX] FAILED to hook GamePrintError\r\n");
		return FALSE;
	}
	Log("[MEMFIX] [OK] Hooked GamePrintError\r\n");

	/* Hook 2: Allocate — VirtualAlloc fallback */
	if (!InstallHook(&g_hkAlloc, pAlloc, Hook_Allocate, STEAL_ALLOC))
	{
		Log("[MEMFIX] FAILED to hook Allocate\r\n");
		return FALSE;
	}
	Log("[MEMFIX] [OK] Hooked Allocate\r\n");

	/* Hook 3: AllocateAligned — VirtualAlloc fallback */
	if (!InstallHook(&g_hkAllocA, pAllocA, Hook_AllocateAligned, STEAL_ALLOCA))
	{
		Log("[MEMFIX] FAILED to hook AllocateAligned\r\n");
		return FALSE;
	}
	Log("[MEMFIX] [OK] Hooked AllocateAligned\r\n");

	/* Hook 4: Free — VirtualFree for tracked pointers */
	if (!InstallHook(&g_hkFree, pFree, Hook_Free, STEAL_FREE))
	{
		Log("[MEMFIX] FAILED to hook Free\r\n");
		return FALSE;
	}
	Log("[MEMFIX] [OK] Hooked Free\r\n");

	/* Hook 5: LoadFromStream — cap instance count to prevent
	 * runaway DynArray growth from corrupted save data */
	BYTE *pLoadStream = base + RVA_LOADSTREAM;
	LogBytes("LoadFromStream ", pLoadStream, 16);

	if (pLoadStream[0] != 0x83 || pLoadStream[1] != 0xEC ||
			pLoadStream[3] != 0x53 || pLoadStream[4] != 0x56)
	{
		Log("[MEMFIX] WARNING: LoadFromStream prologue mismatch! "
				"Expected 83 EC xx 53 56, got %02X %02X %02X %02X %02X\r\n",
				pLoadStream[0], pLoadStream[1], pLoadStream[2],
				pLoadStream[3], pLoadStream[4]);
		Log("[MEMFIX]   Hook 5 SKIPPED — other hooks still active\r\n");
	} else
	{
		if (!InstallHook(&g_hkLoadStream, pLoadStream,
										 Hook_LoadFromStream, STEAL_LOADSTREAM))
		{
			Log("[MEMFIX] FAILED to hook LoadFromStream\r\n");
			/* Non-fatal: other hooks still provide fallback protection */
		} else
		{
			Log("[MEMFIX] [OK] Hooked LoadFromStream"
					" (instance cap = %u)\r\n",
					MAX_INSTANCES);
		}
	}

	/* Hook 6: DynArray_PushBack_8bytes — 8-byte element growth cap */
	BYTE *pPushBack = base + RVA_PUSHBACK;
	LogBytes("DynArrayPush8  ", pPushBack, 16);

	if (pPushBack[0] != 0x56 || pPushBack[1] != 0x8B || pPushBack[2] != 0xF1)
	{
		Log("[MEMFIX] WARNING: DynArray_PushBack prologue mismatch! "
				"Expected 56 8B F1, got %02X %02X %02X\r\n",
				pPushBack[0], pPushBack[1], pPushBack[2]);
		Log("[MEMFIX]   Hook 6 SKIPPED\r\n");
	} else
	{
		if (!InstallHook(&g_hkPushBack, pPushBack,
										 Hook_DynArrayPushBack, STEAL_PUSHBACK))
		{
			Log("[MEMFIX] FAILED to hook DynArray_PushBack\r\n");
		} else
		{
			Log("[MEMFIX] [OK] Hooked DynArray_PushBack_8bytes"
					" (element cap = %u)\r\n",
					MAX_DYNARRAY_ELEMENTS);
		}
	}

	/* Hook 7: DynArray4_PushBack — 4-byte element growth cap.
	 * THIS is the confirmed crash source (via VS debugger stack trace):
	 * Hud::LoadActiveGroups → Hud::PushActiveGroup → DynArray4_PushBack
	 * Corrupt save data causes millions of pushes → doubling → OOM → NULL
	 * → ArrayCopyElements(NULL,...) → write to 0x4 → AV */
	BYTE *pPushBack4 = base + RVA_PUSHBACK4;
	LogBytes("DynArrayPush4  ", pPushBack4, 16);

	if (pPushBack4[0] != 0x56 || pPushBack4[1] != 0x8B || pPushBack4[2] != 0xF1)
	{
		Log("[MEMFIX] WARNING: DynArray4_PushBack prologue mismatch! "
				"Expected 56 8B F1, got %02X %02X %02X\r\n",
				pPushBack4[0], pPushBack4[1], pPushBack4[2]);
		Log("[MEMFIX]   Hook 7 SKIPPED\r\n");
	} else
	{
		if (!InstallHook(&g_hkPushBack4, pPushBack4,
										 Hook_DynArray4PushBack, STEAL_PUSHBACK4))
		{
			Log("[MEMFIX] FAILED to hook DynArray4_PushBack\r\n");
		} else
		{
			Log("[MEMFIX] [OK] Hooked DynArray4_PushBack"
					" (element cap = %u)\r\n",
					MAX_DYNARRAY_ELEMENTS);
		}
	}

	/* Log all loaded modules — helps identify which DLL is making
	 * the runaway allocations (shows up as "external" in stack traces) */
	Log("[MEMFIX] --- Loaded modules ---\r\n");
	{
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
		if (snap != INVALID_HANDLE_VALUE)
		{
			MODULEENTRY32W me;
			me.dwSize = sizeof(me);
			if (Module32FirstW(snap, &me))
			{
				do
				{
					Log("[MEMFIX]   0x%08X - 0x%08X  %ls\r\n",
							(unsigned)(DWORD_PTR)me.modBaseAddr,
							(unsigned)((DWORD_PTR)me.modBaseAddr + me.modBaseSize),
							me.szModule);
				} while (Module32NextW(snap, &me));
			}
			CloseHandle(snap);
		}
	}
	Log("[MEMFIX] --- End modules ---\r\n");

	Log("[MEMFIX] === All hooks installed — fix is ACTIVE ===\r\n");
	return TRUE;
}

/* ================================================================
 * 11. DLL ENTRY POINT
 * ================================================================ */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	(void)lpvReserved;
	char exePath[MAX_PATH];
	GetModuleFileNameA(NULL, exePath, MAX_PATH);
	DWORD pid = GetCurrentProcessId();

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hinstDLL);

		/* Pin this DLL — prevent FreeLibrary from unloading us.
		 * The game loads version.dll temporarily to check its own
		 * file version, then calls FreeLibrary.  Without pinning,
		 * our inline hooks would jump to freed memory → crash. */
		HMODULE hSelf;
		// FIX 1: Use hinstDLL instead of DllMain.
		// hinstDLL is the true base memory address of your proxy DLL.
		BOOL pinned = GetModuleHandleExA(
				GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
						GET_MODULE_HANDLE_EX_FLAG_PIN,
				(LPCSTR)hinstDLL,
				&hSelf);

		Log("[MEMFIX] ATTACHING to Process ID: %lu | EXE: %s\r\n", pid, exePath);

		// Add GetLastError() to your log so you know EXACTLY why it failed if it does.
		if (!pinned)
		{
			Log("[MEMFIX] DLL PIN FAILED. System Error Code: %lu\r\n", GetLastError());
		}
		else
		{
			Log("[MEMFIX] DLL successfully pinned to process.\r\n");
		}

		/* 1. Forward version.dll API */
		LoadRealVersionDLL();

		/* 2. Init infrastructure */
		InitializeCriticalSection(&g_trackCS);
		LogInit();

		Log("[MEMFIX] =============================================\r\n");
		Log("[MEMFIX]  DXHR:DC Memory Fix v1.6  (version.dll proxy)\r\n");
		Log("[MEMFIX] =============================================\r\n");

		/* Install vectored exception handler for crash diagnostics.
		 * First arg = 1 means "insert at front of handler list". */
		AddVectoredExceptionHandler(1, Veh_CrashLogger);
		Log("[MEMFIX] Vectored exception handler installed\r\n");

		/* 3. Install hooks */
		if (!InstallAllHooks())
		{
			Log("[MEMFIX] Hook installation FAILED.\r\n");
			/* Don't show a MessageBox here — it might block game
			 * startup. The log file has details. */
		}

	}
	else if (fdwReason == DLL_PROCESS_DETACH)
	{
		Log("[MEMFIX] DETACHING from Process ID: %lu | EXE: %s | lpvReserved: %p\r\n", pid, exePath, lpvReserved);
		if (lpvReserved != NULL)
		{
			// Process is truly exiting. It is safe to clean up here.
			Log("[MEMFIX] Process exiting. Tracked allocs remaining: %ld\r\n", g_trackedCount);

			if (g_console)
			{
				FreeConsole();
			}
			if (g_logFile != INVALID_HANDLE_VALUE)
			{
				CloseHandle(g_logFile);
				g_logFile = INVALID_HANDLE_VALUE;
			}

			// CAUTION: Calling FreeLibrary inside DllMain is risky due to Loader Lock.
			// During process termination, Windows cleans up modules anyway, so you can safely omit this.
			if (g_realVersion)
			{
				FreeLibrary(g_realVersion);
			}

			DeleteCriticalSection(&g_trackCS);
		} else
		{
			// lpvReserved is NULL! The game called FreeLibrary on your proxy.
			// If your pinning was successful, you shouldn't be hitting this.
			Log("[MEMFIX] WARNING: Dynamic unload attempted! Preserving console.\r\n");

			// We do NOT destroy the console or critical sections here.
		}
	}

	return TRUE;
}
