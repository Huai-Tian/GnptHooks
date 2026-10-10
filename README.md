# GnptHooks

[简体中文](README_ZH.md) | English | [AI collaboration doc](README_AGENT.md)

## 📖 Introduction

**GnptHooks** is a kernel-function hook framework for Windows (Windows 10 x64) on **AMD** processors, built as a Type-1 hypervisor (AMD SVM + nested paging).

It virtualizes the running system and intercepts function execution through **per-core dual NPT views** — your driver can hook any kernel function **without modifying a single byte of the original memory, and with zero VM-Exits per hit in steady state**. Measured: 4.6M+ interceptions on physical hardware with the NPF exit counter pinned at one-per-core for the entire run.

> **Using an AI assistant (Copilot / Claude / GPT ...) for development on this project?** Read [README_AGENT.md](README_AGENT.md) first — it contains the project's counter-intuitive safety designs, hard red lines, and bugcheck case studies. Skipping it and editing code directly is very likely to introduce bugcheck-grade defects.

> **Intel machine?** This is the AMD/SVM sibling of GeptHooks (Intel VT-x/EPT). Independent projects, zero symbol overlap; designs are cross-referenced, code is not shared.

## ✨ Three hook modes

Pick a mode per target (`Hook.Flags` at install time); all three co-exist on the same machine:

| | Normal (CodePage) | TRANSPARENT (DR) | NX-FENCE |
|---|---|---|---|
| Flag | `0` | `HOOK_TRANSPARENT` | `HOOK_NXFENCE` |
| Mechanism | shadow page via NPT views | hardware execution breakpoint (DR0-3) | page NX + re-arm on return |
| Read transparency | no — shadow view is readable | **structural** (original page untouched) | **structural** (both views carry original bytes) |
| PatchGuard-covered targets | forbidden (0x109 bugcheck) | safe | safe |
| Steady-state exits per call | **0** | 1 | 2 |
| Capacity | one hook per page (first-match) | ≤ 4 per core (DR hardware count) | unlimited (entry count only; must own its page) |
| Best for | cold, non-PG-covered targets | hot targets (≥100/s) and PG-covered targets | PG-covered targets at scale, or when intercept semantics are needed |

**Normal mode (CodePage)** — the signature zero-exit hook. The *Primary* view maps the hook page non-executable (data reads/writes stay perfectly normal); the *Secondary* view remaps it to a shadow copy carrying a 14-byte absolute jump at the target offset. The first fetch on that page costs one NPF exit per core; every later hit is pure guest-mode translation with **no exit at all**. Guest writes to the shadow view fault and are forwarded to the real page — bookkeeping stays coherent while callers never observe the shadow. A fail-loud reject gate refuses targets whose prologue is shorter than the patch (a control-transfer instruction inside the 14-byte window = install-time rejection), so out-of-bounds writes into neighboring code are structurally impossible.

**TRANSPARENT mode (DR)** — arms a hardware execution breakpoint (DR0-3, execute-only) on the target's entry linear address. The original page is never touched: any external reader (PatchGuard, kernel scanners) sees original bytes at all times — read/write transparency holds **structurally**. Exactly 1 VM-exit per call, no page-heat constraint; measured 2,535 #DB exits/s sustained for 600 s, all green. The guest's debug subsystem stays bare-metal-equivalent: its own breakpoints and TF single-step traps are delivered faithfully (`int1`/`ICEBP` pass through, DR readback follows architectural semantics), and while the guest is actively debugging through the entry the hook silently yields that call — bare-metal behavior wins over interception. Your own breakpoints are absorbed by MOV-DR shadow emulation, same semantics as KVM/VMware debug shadows.

**NX-FENCE mode** — fills the remaining matrix corner: **PG-safe × unlimited capacity**. The target page is marked NX in the Primary view (data fully transparent) and stays identity-RWX in the Secondary; the entry fetch faults, the engine redirects to the trampoline, and the callback's return path re-arms the fence. Zero artifacts in either view; steady-state cost = 2 exits per call (entry fault + re-arm). Choose cold or page-isolated targets — neighbor functions on the same page amplify exit flow.

## 🛡️ Engine capabilities

- **Detour with full control** — your callback receives the original arguments, can call the original (`GnptCallOriginal`), modify arguments or return values, or swallow the call entirely.
- **Stack-argument forwarding** — declare the target's 5th+ (stack) argument count (up to 32); the callback gets a live, writable `StackArgs` pointer, modifications forwarded through `GnptCallOriginal`.
- **Version-independent trampolines** — generated at runtime by an LDE relocation engine: per-instruction decode, RIP-relative fixups, far targets rewritten to equivalent `mov reg, imm64` absolute loads; unrelocatable prologues are rejected at install time. An execution-grade unit test ships in `DbgTools/test_reloc.c`.
- **In-image trampoline slots (code caves)** — trampoline slots are carved into the driver image's own executable-section tail fragments: branch sources point inside a module (a normal LBR stack) and no executable pool pages appear in the address space. Pool fallback exists only for images without usable caves.
- **MSR interception API** — per-core MSRPM bitmaps; read-forging and write-monitor callbacks on any MSR inside the architecturally-covered ranges (`GnptMsrHookInstall` / `GnptMsrReadReal`); un-hooked MSRs cost zero exits.
- **CPUID hypervisor concealment** — taken-over cores report the SVM bit cleared (self-consistent with the VM_CR read forge), signature-less leaves zeroed, max-leaf never shrunken. Verified with Task Manager reporting *Virtualization: Disabled* on every core through a full all-core session.
- **NPT self-concealment** — the engine's own page-table pages (~2,100) are remapped to a zero page in the guest's view; a guest-side scanner reads back zeros for the entire nested-paging hierarchy, zero exits in steady state.
- **TSC timeline compensation** — every exit path accounts its cost into a TSC-offset watermark, clamped cross-core: timing-based hypervisor detection sees a uniformly slowed clock, never a negative delta.
- **Debug-subsystem fidelity** — TF single-step, self-set breakpoints, architectural DR readback, `int1`/`ICEBP` software traps: all delivered faithfully; root-resident branches never leak into the guest LBR stack.
- **Observability governed by build type** — Debug builds = full observability (file log + event ring + BSOD black-box watchdog); Release builds = zero logging code in the binary. No runtime/registry switches by design.
- **Clean delivery form** — the driver entry runs the framework lifecycle plus one demo hook; `main.c` is yours to replace. The framework is consumed as source.

## 📐 How the zero-exit hook works

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
  → per-hook trampoline slot (in-image code cave; mov r10, entry;
    jmp GnptStubEntry)
  → GnptStubEntry: SAVE_ALL → dispatch to your callback
      (may GnptCallOriginal: calls the original via the LDE-relocated
        trampoline — view-independent; other hook targets invoked from
        the callback trigger normally = standard detour semantics)
    → RESTORE_ALL
  ← caller (RAX = your callback's return value)
```

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

Debug logging needs no switches: build the **Debug configuration** for full observability; **Release builds** ship zero logging code.

## 🧩 Using the API

```c
#include "hook.h"

// Your detour callback: runs in the original function's thread and
// IRQL context. Return value becomes the hook's return value.
// StackArgs: array of the 5th+ (stack) arguments — readable and
// writable; modifications are forwarded by GnptCallOriginal.
static ULONG64 OnNtClose(PVOID Context,
    ULONG64 Arg1, ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4,
    ULONG64* StackArgs)
{
    ULONG64 status = GnptCallOriginal(Arg1, Arg2, Arg3, Arg4);
    return status;   // or forge it — you have full control
}

UNICODE_STRING name;
RtlInitUnicodeString(&name, L"NtClose");
GNPT_HOOK Hook = { 0 };
Hook.Target    = MmGetSystemRoutineAddress(&name);  // PUNICODE_STRING!
Hook.Callback  = OnNtClose;
Hook.Context   = NULL;
Hook.StackArgs = 0;        // number of the target's 5th+ stack arguments
Hook.Flags     = 0;        // 0 / HOOK_TRANSPARENT / HOOK_NXFENCE

GnptHookInstall(&Hook);
// ... hooks are live on all cores ...
GnptHookRemove(Hook.Target);
```

**Contracts** (full discipline list lives in `hook.h` — it is authoritative):

1. Callbacks run in the original function's thread and IRQL context (up to DISPATCH_LEVEL) — IRQL-safe work only (interlocked operations, lock-free ring events, `GnptCallOriginal`).
2. Always call the original through `GnptCallOriginal`; calling the target entry directly runs into the jump code under the Secondary view.
3. **Target selection**: hot targets (≳100 calls/s) → TRANSPARENT (measured verdict: same function, same 152k-hits/600s flow — CodePage mode produced a DWM crash loop, DR mode zero events); PG-covered targets → TRANSPARENT or NX-FENCE, never normal mode; NX-FENCE targets must not share a page with any other hook (install rejects).
4. `GnptHookInstall/Remove/Enumerate` are single-writer — serialize calls yourself (a dedicated thread or a mutex).
5. Unload order: `GnptHookRemoveAll` before SVM teardown, `GnptHookFreeMemory` after — see `main.c`'s `DriverUnload` for the reference sequence.

## ⚙️ Requirements

- **CPU**: AMD with SVM + nested paging (NPT) + NRIPS (checked at start; missing features = clean rejection, never a partial takeover)
- **OS**: Windows 10 x64 (verified on Zen 3 mobile and Zen 5 desktop; other generations expected to work — verify on your hardware)
- **Hypervisor conflicts**: Hyper-V / VBS / Memory Integrity / Windows Hypervisor Platform must be disabled — GnptHooks must be the root hypervisor
- **Nested testing**: runs under VMware nested SVM for bring-up; nested environments distort feature bits — anomalies observed in a VM must be reproduced on physical hardware before being treated as bugs
- **Test signing**: `bcdedit /set testsigning on`, or sign the driver properly
- **Build**: Visual Studio 2022 + Windows Driver Kit (WDK)
- **Core-takeover dose** (`GNPT_TAKE_CORES` in `common.h`): default takes over all cores — the only form in which the CPUID disguise is complete. On dose-sensitive platforms (see below) build with a lower count for daily development and reserve all-core sessions for short verification bursts after a cold boot.

## 🖥️ Platform Hazards

Read this before running a bare-metal hypervisor on AMD hardware.

**Sub-SMM killer (silent hardware reset).** On some AMD mobile platforms (observed: Cezanne / Zen 3 with EOL OEM firmware), a sparse external event below SMM (likely SMU/EC class) silently resets the machine while all cores are guest-parked. Signature: hardware reset with no bugcheck, no WHEA record, no log precursor — even with no driver loaded. Not fixable in software: `HWCR.SMMLOCK=1` blocks SMI interception, making the killer invisible to both the OS and the VMM.

**Dose-sensitive desktop platforms.** On some desktop hardware (observed: AM5 / Zen 5), all-core SVM residency behaves like a *consumable budget*: sessions die after a time that shrinks as the budget is consumed (silent reset, or CLOCK_WATCHDOG_TIMEOUT with a wedged core — two outward forms of the same event). The budget is not reset by the crash; it recovers only with minutes-to-hours of non-residency. Ruled out experimentally: C-state depth, load level, specific applications, and every software-visible surface. Low-dose builds stay healthy through full test suites. Mitigations that work: dose control + session-length control.

**Operational discipline on affected platforms.** Cold machine + load late after boot + default power plan + short bursts; finish verification and unload within minutes; never re-test right after a death (that is when the reset loop is hottest). A cold first run after overnight power-off is the most stable window observed.

**Hardware feature boundaries** (probed at boot, reported honestly in the log banner): PMC/IBS virtualization is absent on some Zen 3 consumer APUs (the PMU side channel cannot be closed in hardware there); TSC_DEADLINE translation engages only when the LAPIC actually runs in TSC-deadline mode; STGI passthrough is gated on the SKINIT CPUID bit.

**Hardware selection guidance.** AMD microcode reaches consumers only through BIOS/AGESA updates from the OEM. A platform whose OEM has stopped BIOS updates is a hard risk for any bare-metal hypervisor. Prefer boards with an active AGESA cadence.

## ⚠️ Project Status

Milestones M0–M16 have graduated on physical hardware (two AMD platforms: Ryzen 7 5800H 16-core, Ryzen 5 9600X 12-core). Highlights: the dual-NPT zero-exit engine (M0–M5), TSC compensation and the three-body-race root cause (M6, M9), NPT self-concealment and the stability campaign (M8), the self-consistent "SVM inactive" story (M11), CPUID concealment as a shipping feature (M13), the four-entity death forensics (M14), DR-based TRANSPARENT rework with debug-subsystem fidelity (M15), and the M16 exposure-surface closure: the NX-FENCE third mode (PG-safe × unlimited capacity), in-image code-cave trampoline slots, the DWM crash family root-caused and closed (hot-target discipline), and two low-level case laws (CET shadow-stack × CR0.WP interlock; MDL aliasing contract on non-paged builds). Every claim above has a log-level evidence chain, kept as internal case law outside the repository. Current build: **v0.9cq**.

Headline verification numbers: 4.6M+ zero-exit interceptions (NPF pinned at one-per-core); 2,535 DR-mode exits/s sustained 600 s green; 136,377 triggers/600 s through in-image cave slots with byte-exact teardown; 3,003 s all-core session; clean unload with SVME read-back = 0 on every core and exact NPT page accounting.

The framework remains research-grade: a hypervisor-level bug may still bugcheck the system — always test on a disposable machine.

## 🚫 Non-Commercial Statement

This project is initiated by the developer out of personal interest and for technical research purposes, and is **non-commercial** in nature:

- **Permanently Free**:
This project is completely free, with **no paid features, memberships, subscriptions, or in-app purchases**. All features are fully accessible to all users.

- **No Sponsorship Channels**:
The author has **never opened any sponsorship channels**, nor does the author **accept any financial donations** — to maintain the project's neutrality and purity.

- **Non-Profit Purpose**:
This project involves no commercial operations, and the author derives no direct or indirect economic benefit from it.

- **Research-Oriented**:
This project is consistently positioned for **security research, driver development, and software testing** — providing a research tool for the community, not a commercial product. Any commercial use of this project is the user's own initiative and is unrelated to this project.

- **License is GPL-3.0 only — no commercial exceptions.**
This project is offered under the terms of the GPL-3.0 (see LICENSE),
and every use must comply with that license in full. What GPL requires —
source availability and the same license for derivatives — is exactly what
it means to use this project. Commercial use that cannot accept
GPL terms does not have the author's authorization: the author does not
offer, and will not negotiate, dual licensing, commercial exceptions, or
proprietary redistribution. Reselling this project for profit while
ignoring GPL obligations is copyright infringement.

- **Attribution and statement integrity:**
Redistribution of unmodified builds is permitted only together with
this statement and proper attribution. Removing, altering, or obscuring
this non-commercial statement when redistributing is prohibited.

- **Official channels only:**
Obtain this project only from this repository (GitHub) or other
officially designated channels. Builds from any other source are
unofficial, unverified, and used entirely at the downloader's own risk.

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

If you find this project helpful, or recognize its value in technical research, consider giving it a ⭐ on GitHub.

Your support helps more people discover this project, and also lets the author feel the significance of continued maintenance.

Thank you for your recognition.
