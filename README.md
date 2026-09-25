# GnptHooks

[简体中文](README_ZH.md) | English | [AI collaboration doc](README_AGENT.md)

## 📖 Introduction

**GnptHooks** is a hidden NPT hook framework for Windows (Windows 10 x64) on **AMD** processors.

It virtualizes the running system with AMD SVM and uses **per-core dual NPT views (Primary / Secondary)** to intercept function execution — letting your driver hook any kernel function **without modifying a single byte of the original memory, and with zero VM-Exits per hook hit in steady state**.

The redirection is performed purely by nested-page-table translation. The *Primary* view is an identity mapping with the hook page marked non-executable (data reads and writes stay perfectly normal); the *Secondary* view remaps the hook page to a shadow copy (an absolute jump at the target offset). The first instruction fetch on the hooked page triggers a single NPF (#VMEXIT 0x400) on which the engine switches that core to the Secondary view — every later hit on that core is a pure guest-mode detour with **no exit at all**. Measured: 26,081 NtClose interceptions with the NPF counter pinned at one-per-core (2 on a 2-core VM) for the entire run.

> **Using an AI assistant (Copilot / Claude / GPT ...) for development on this project?** Read [README_AGENT.md](README_AGENT.md) first — it is written specifically for AI and contains the project's many **counter-intuitive safety designs and hard red lines** (plus every bugcheck case study). Skipping it and editing code directly is very likely to introduce bugcheck-grade defects.

> **Intel machine?** This is the AMD/SVM sibling of GeptHooks (Intel VT-x/EPT). The two are independent projects with zero symbol overlap; designs are cross-referenced, code is not shared.

## ✨ Features

- **Dual-NPT steady-state zero-VM-Exit detour**
  Every core holds two NPT views: *Primary* (identity, hook page NX — reads/writes fully transparent) and *Secondary* (hook page remapped to the shadow CodePage). A hit = translation, not a trap: **each core pays exactly one NPF exit on the first hit of a hook, then zero exits forever**. Measured: 26,081 NtClose interceptions over a nested-VM session with the NPF exit counter constant at one-per-core.

- **Detour with full control**
  Your callback receives the original arguments, can call the original function (`GnptCallOriginal`), modify arguments or return values, or swallow the call entirely. No prologue replay at hook time — the shadow page carries the relocated prologue; the original page is never written.

- **Stack-argument forwarding (5th argument and beyond)**
  Declare the target's stack-argument count in `GNPT_HOOK.StackArgs` (up to 32); your callback receives a `StackArgs` pointer to the live arguments on the trigger stack — readable and **writable**, with modifications forwarded through `GnptCallOriginal`. No argument gaps when hooking multi-parameter kernel functions.

- **Version-independent trampolines**
  Trampolines are generated at runtime by an LDE relocation engine — per-instruction decode, RIP-relative fixups (near targets re-based; targets beyond ±2 GB are rewritten to equivalent `mov reg, imm64` absolute loads, so no syscall-stub prologue is rejected for distance alone), rejection of relative branches, and a CPU-view back-scan self-check before going live. No hardcoded prologues bound to one Windows build; unrelocatable prologues are rejected at install time. An execution-grade unit test (`tests/test_reloc.c`, user-mode x64) runs generated trampolines on a real CPU to prove semantic equivalence.

- **Write-transparency by construction**
  The Secondary view maps the hook page as read-only: any guest write to the page faults (NPF) and the engine forwards it to the Primary view, where the write lands on the real original page — hook bookkeeping pages stay coherent while callers never observe the shadow copy.

- **TRANSPARENT mode: read-transparency for scanner-grade stealth**
  Install with `HOOK_TRANSPARENT` and the engine arms **four static NPT views** (P / HOOKS / HIDE / EXEC, one ASID each — view switches are pure NCR3+ASID writes: zero PTE writes, zero TLB flushes). In the hiding state the hook page is simply *not present*: any external read (PatchGuard, scanners) faults and is served the **original bytes** through a single-step window — AMD has no MTF, so the engine injects TF, claims the #DB, and re-hides. Executing the target opens a one-instruction EXEC window that detours, then re-hides. A leak-defense net (per-exit window liveness check, permanent #DB intercept, interrupt-frame TF scrubbing) makes sure the single-step machinery can never surface a guest-visible #DB. Best for low-traffic targets — each stepped instruction costs 2 VM-Exits.

- **Observability governed by build configuration**
  The whole observation stack (writer threads, binary event ring, BSOD black-box watchdog) is governed by the build type: **Debug builds = full observability** (authoritative log in `C:\Windows\Temp\gnpt_log.txt`, desktop mirror; if logging stalls for 30 s the watchdog deliberately bugchecks to capture a memory dump — a debugging aid, never part of a delivery build); **Release builds = zero logging code in the binary**. Deliberately no runtime/registry switch — a registry value is both a static signature an AV/EDR can flag and a footprint left on the target.

- **Clean delivery form**
  The driver entry runs only the framework lifecycle (resource allocation → per-core virtualization launch → resident) plus one demo hook (`main.c` is yours to replace). The framework is consumed as source — add the files to your own driver project.

## 📐 How the zero-VM-Exit hook works

```
                Primary view                   Secondary view
                ┌────────────┐               ┌────────────┐
                │ identity,  │               │ hook page  │
                │ hook page  │               │ → CodePage │
                │ NX (X=0)   │               │ (X=1, W=0) │
                └─────┬──────┘               └─────┬──────┘
                      │ data R/W transparent       │ → shadow copy (CodePage)
   guest ─────────────┴────────────────────────────┴─────────────────
        first fetch on hook page: NPF → engine switches this core to
        Secondary (TLB flush) — every later hit is pure translation
```

Hook trigger chain (guest mode only, zero VM-Exit):

```
caller → target function (Secondary view = CodePage, 14-byte absolute
  jump at the target offset)
  → per-hook trampoline slot (mov r10, entry; jmp GnptStubEntry)
  → GnptStubEntry: SAVE_ALL → dispatch to your callback
      (may GnptCallOriginal: calls the original via the LDE-relocated
        trampoline — view-independent; other hook targets invoked from
        the callback trigger normally = standard detour semantics)
    → RESTORE_ALL
  ← caller (RAX = your callback's return value)
```

View-switch engine (`GnptHookNpfEngine`): a fetch NPF on a hooked page in Primary → switch to Secondary; a write NPF on the shadow page in Secondary → switch back to Primary (the write then lands on the real page). In the common case the core simply *stays* in Secondary — measured runs show the NPF counter frozen at one-per-core while interception counts grow unbounded.

## 🚀 Quick Start

Install and start the driver:

```
sc create GnptHooks type= kernel start= demand binPath= "C:\path\to\GnptHooks.sys"
sc start GnptHooks
```

Stop and uninstall (all hooks are removed cleanly first, then SVM is torn down on all cores via the STOP bridge):

```
sc stop GnptHooks
sc delete GnptHooks
```

Debug logging needs no switches: just build the **Debug configuration** for full observability (file log + event ring + black-box watchdog); **Release builds** ship zero logging code.

## 🧩 Using the API

```c
#include "hook.h"

// Your detour callback: runs in the original function's thread and
// IRQL context. Return value becomes the hook's return value.
// StackArgs: array of the 5th+ (stack) arguments — readable and
// writable; modifications are forwarded by GnptCallOriginal.
// NULL when StackArgs was not declared at install time.
static ULONG64 OnNtClose(PVOID Context,
    ULONG64 Arg1, ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4,
    ULONG64* StackArgs)
{
    ULONG64 status = GnptCallOriginal(Arg1, Arg2, Arg3, Arg4);
    return status;   // or forge it — you have full control
}

// Install / remove
UNICODE_STRING name;
RtlInitUnicodeString(&name, L"NtClose");
GNPT_HOOK Hook = { 0 };
Hook.Target    = MmGetSystemRoutineAddress(&name);  // PUNICODE_STRING!
Hook.Callback  = OnNtClose;
Hook.Context   = NULL;
Hook.StackArgs = 0;   // number of the target's 5th+ stack arguments (0 = off)

GnptHookInstall(&Hook);
// ... hooks are live on all cores ...
GnptHookRemove(Hook.Target);
```

Hooking functions with six or more parameters (stack arguments) — just declare the count:

```c
// Target prototype: ULONG64 F(ULONG64 A1..A4, ULONG64 A5, ULONG64 A6);
GNPT_HOOK Hook = { 0 };
Hook.Target    = (PVOID)F;
Hook.Callback  = OnF;
Hook.StackArgs = 2;               // two stack arguments (A5/A6)

static ULONG64 OnF(PVOID Ctx, ULONG64 A1, ULONG64 A2,
    ULONG64 A3, ULONG64 A4, ULONG64* StackArgs)
{
    StackArgs[0] ^= 1;            // modify the 5th argument — takes effect on forwarding
    return GnptCallOriginal(A1, A2, A3, A4);  // stack arguments forwarded automatically
}
```

**Callback context contract**:

1. Callbacks run in the original function's thread and IRQL context (up to DISPATCH_LEVEL) — only perform IRQL-safe work inside (interlocked operations, lock-free ring events, `GnptCallOriginal`).
2. Always call this hook's original through `GnptCallOriginal` — it invokes the original via the version-independent relocated trampoline and forwards stack arguments automatically (calling the original entry directly would run into the jump code under the Secondary view).
3. Nesting semantics (standard detour): other hook targets invoked from within your callback **trigger normally**.

On unload, remove all hooks **before** SVM teardown (`GnptHookRemoveAll` — in-flight callbacks complete safely), then free memory **after** it (`GnptHookFreeMemory`) — see `main.c`'s `DriverUnload` for the reference sequence.

## ⚙️ Requirements

- **CPU**: AMD with SVM + nested paging (NPT) + NRIPS (checked at start; missing features = clean rejection, never a partial takeover)
- **OS**: Windows 10 x64 (Zen 3 baseline; other AMD generations expected to work — verify on your hardware)
- **Hypervisor conflicts**: Hyper-V / VBS / Memory Integrity / Windows Hypervisor Platform must be disabled — GnptHooks must be the root hypervisor
- **Nested testing**: runs under VMware nested SVM for development; nested environments distort some feature bits — anomalies observed in a VM must be reproduced on physical hardware before being treated as bugs
- **Test signing**: enable with `bcdedit /set testsigning on`, or sign the driver properly
- **Build**: Visual Studio 2022 + Windows Driver Kit (WDK)
- **Runtime**: administrator privileges

## 🧪 Capability Verification Matrix

Core paths verified on nested AMD SVM (VMware guest, Windows 10 x64) — base engine at v0.3c (2-core), single-step & stealth suite at v0.7d (4-core):

| Capability | Measured evidence |
|---|---|
| All-core SVM takeover | per-core vmrun → probe self-certification ('W'/'Q' rings) → clean unload, stable across runs (2-core and 4-core) |
| Multi-view NPT build | Static identity trees (4 views), 512 GB coverage, banner logs all NCR3 values |
| Steady-state zero-exit interception | 26,081 NtClose hits; NPF exit counter constant at one-per-core for the whole session |
| NPF view-switch engine | Cores switched to the hook view on first hooked fetch (error code 0x100000015 = P+ID bits, exactly the armed layout); no further NPF |
| Full detour control | Callback dispatch / CallOriginal / demo counter all confirmed via ring breadcrumbs ('V'/'H'/'h'/'O') |
| Version-independent trampolines | LDE back-scan self-check passed; far RIP-relative targets (ZwPowerInformation stub) relocated via `mov reg, imm64` rewrite; execution-grade unit test all green |
| TRANSPARENT read-transparency | v0.7d: ZwPowerInformation stub demo — 3 self-triggered + 17 real kernel callers (dwm/dxgkrnl path) intercepted; every external access served original bytes; zero guest-visible #DB |
| Single-step window leak defenses | v0.7d: 265 s soak at ~680 step-windows/s (180k windows) all closed; leak crumbs ('L'/'D') self-healed with zero system impact; r70/r41 exit ratio ~0.11 (vs. 0.8 storm before the fix) |
| Clean removal | CodePage bytes restored + view PTEs reverted to identity + all-core TLB sync; new hook hits stop immediately after Remove |
| Atomic unload | All cores STOP bridge with SVME read-back = 0; zero leaked cores; NPT pages fully released (accounting exact) |
| Release delivery form | Log-free build compiles clean (Fl\* macros collapse to no-ops) |

Physical-hardware final verification (NPF-counter criteria, ASID no-flush switching) is on the roadmap — see Project Status.

## ⚠️ Project Status

Milestones M0 (skeleton + observation stack), M1 (SVM world switch), M2 (NPT identity mapping), M3 (dual-NPT hook engine), M4 (TF+#DB single-step primitives) and M5 (four-view TRANSPARENT stealth suite with leak defenses) have graduated from staged testing **on nested virtualization** — the v0.7d build passed a full end-to-end run: 20 real interceptions over a 265 s soak, every single-step window closed, clean unload with zero leaked cores. Remaining: long-duration PatchGuard soak, physical-hardware final verification, M6 clock domains, M7 root hardening + release. The framework is research-grade: a hypervisor-level bug may still bugcheck the system — always test on a disposable machine.

## 🚫 Non-Commercial Statement

This project is initiated by the developer out of personal interest and for technical research purposes, and is **non-commercial** in nature:

- **Permanently Free**:
This project is completely free, with **no paid features, memberships, subscriptions, or in-app purchases**. All features are fully accessible to all users.

- **No Sponsorship Channels**:
The author has **never opened any sponsorship channels**, nor does the author **accept any financial donations** — to maintain the project's neutrality and purity.

- **Non-Profit Purpose**:
This project involves no commercial operations, and the author derives no direct or indirect financial benefit from it.

- **Research-Oriented**:
This project is consistently positioned for **security research, driver development, and software testing** — providing a research tool for the community, not a commercial product. Any commercial use of this project is the user's own initiative and is unrelated to this project.

- **Resale Prohibited**:
Resale, redistribution for profit, or commercial use of this project is strictly prohibited. Please obtain it only from this repository (GitHub) or other officially designated channels. The developer assumes no responsibility for any issues arising from unofficial sources.

## ⚖️ Disclaimer

- **Purpose Limitation**:
This project is intended for **security research, driver development, software testing, and educational purposes** only.
Do not use this project for any illegal purposes (including but not limited to malware development, anti-cheat evasion, data theft, and system compromise).

- **Consequences Warning**:
Hooking with this framework **may violate the terms of service of third-party software and the laws of your jurisdiction**.
You should assess the risks before using it. The developer and contributors **are not responsible for any account bans, legal liabilities, or other consequences** arising from such use.

- **System Stability**:
A hypervisor-level driver operates with the highest privilege on your machine. **A bug may bugcheck (BSOD) the system or corrupt data.** Always test in a virtual machine or on a disposable machine, and keep backups.

- **No Warranty**:
This software is provided under the terms of its license, **without any express or implied warranties**, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement.

- **Compatibility Disclaimer**:
This software **does not guarantee full compatibility with all Windows versions, CPU models, or firmware**. The developer assumes no responsibility for functional issues or losses caused by system updates, microcode changes, or other uncontrollable factors.

- **Limitation of Liability**:
To the fullest extent permitted by applicable law, **in no event shall the author or contributors be liable** for any direct, indirect, incidental, special, or consequential damages arising out of or in connection with the use or inability to use this software, even if advised of the possibility of such damages.

- **User Responsibility**:
Users assume all legal responsibilities arising from the use of this project.

- **Final Interpretation**:
The final interpretation of this disclaimer belongs to the author of this project.

## 💬 Contact

You are welcome to submit issues, suggestions, and bug reports via GitHub Issues.

## ⭐ Support the Project

If you find this project helpful, or if you recognize its value in technical research, consider giving it a ⭐ on GitHub.

Your support helps more people discover this project, and also lets the author feel the significance of continued maintenance.

Thank you for your recognition.
