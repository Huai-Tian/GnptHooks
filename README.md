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

- **Target resolution is the caller's responsibility (EPT-contract)**
  `GNPT_HOOK.Target` is a plain function pointer — you resolve the name to an address yourself (e.g. `MmGetSystemRoutineAddress` for exported routines). The framework deliberately carries **zero Windows-internal-structure dependencies**: no SSDT locator, no version-chasing signature scanning. Anything exported by name resolves through the public API; unexported Nt-routine resolution, if you need it, belongs in your code where you control the version risk. Same contract as the sibling project GeptHooks.

- **Stack-argument forwarding (5th argument and beyond)**
  Declare the target's stack-argument count in `GNPT_HOOK.StackArgs` (up to 32); your callback receives a `StackArgs` pointer to the live arguments on the trigger stack — readable and **writable**, with modifications forwarded through `GnptCallOriginal`. No argument gaps when hooking multi-parameter kernel functions.

- **Version-independent trampolines**
  Trampolines are generated at runtime by an LDE relocation engine — per-instruction decode, RIP-relative fixups (near targets re-based; targets beyond ±2 GB are rewritten to equivalent `mov reg, imm64` absolute loads, so no syscall-stub prologue is rejected for distance alone), rejection of relative branches, and a CPU-view back-scan self-check before going live. No hardcoded prologues bound to one Windows build; unrelocatable prologues are rejected at install time. An execution-grade unit test (`DbgTools/test_reloc.c`, user-mode x64) runs generated trampolines on a real CPU to prove semantic equivalence.

- **Write-transparency by construction**
  The Secondary view maps the hook page as read-only: any guest write to the page faults (NPF) and the engine forwards it to the Primary view, where the write lands on the real original page — hook bookkeeping pages stay coherent while callers never observe the shadow copy.

- **Target-selection boundary (PatchGuard)**
  The Secondary view stays **readable** in normal mode: external readers (PatchGuard, kernel scanners) see the CodePage jump bytes there — for PatchGuard-covered targets (SSDT / system services) this ends in a 0x109 bugcheck (PG checks fire on a randomized schedule; surviving a short soak proves nothing — v0.9d ran with NtClose hooked for ~74 minutes before being killed; v0.9bu dump forensics matched KeInitializeDpc exactly in P3). Use normal mode only on non-PG-covered ordinary kernel functions; for covered targets use the TRANSPARENT mode below (up to 4 per core). AMD NPT has no exec-only permission bit, so normal mode cannot get read-transparency for free.

- **TRANSPARENT mode: DR execution-breakpoint entry trap (structural read/write transparency)**
  Install with `HOOK_TRANSPARENT` and the engine arms a **hardware execution breakpoint** (DR0-3, execute-only, 1 byte) on the target's entry linear address — the original page is **never touched**: any external reader (PatchGuard, scanners) sees original bytes at all times, so read/write transparency holds **structurally** rather than being bought with runtime windows. The entry instruction fetch raises a #DB fault (before execution) which root redirects to the trampoline slot (equivalent to the patched jump); CallOriginal then replays the prologue through the relocation trampoline and the rest of the function executes from the original page — exactly 1 VM-Exit per target call, zero translation flips (op-cache stale-decode races are structurally absent), and no page-heat constraint. Boundaries: ≤4 per core (DR hardware count, install fails loud beyond that); the guest's own debug breakpoints are absorbed by MOV DR shadow emulation (same semantics as KVM/VMware debug shadows); mechanically orthogonal to normal mode and freely co-resident. The guest debug subsystem stays bare-metal-equivalent throughout: the guest's own breakpoints and TF single-step traps are delivered faithfully (the hook silently yields a call while the guest is single-stepping through the entry — probe-time yield, with the resume flag set so the consumed breakpoint does not refire), `int1`/`ICEBP` software traps reach their handlers instead of being swallowed (the classic anti-hypervisor probe), and DR readback follows architectural semantics (DR7 readback always carries bit10 RA1).

- **Observability governed by build configuration**
  The whole observation stack (writer threads, binary event ring, BSOD black-box watchdog) is governed by the build type: **Debug builds = full observability** (authoritative log in `C:\Windows\Temp\gnpt_log.txt`, desktop mirror; if logging stalls for 30 s the watchdog deliberately bugchecks to capture a memory dump — a debugging aid, never part of a delivery build); **Release builds = zero logging code in the binary**. Deliberately no runtime/registry switch — a registry value is both a static signature an AV/EDR can flag and a footprint left on the target.

- **MSR interception API (read forge / write monitor)**
  Per-core MSR permission bitmaps (MSRPM) let your hook trap RDMSR/WRMSR on any MSR inside the three architecturally-covered ranges: a read callback returns the value the guest sees (forge LSTAR, EFER, whatever), a write callback either passes the write through (faithfully re-executed in root, semantics identical to passthrough) or silently swallows it. Out-of-range MSRs (e.g. 0x40000000+) auto-exit and are replayed with true values — bare-metal equivalent, guaranteed by the dispatcher. Un-hooked MSRs cost zero exits (hardware walks the bitmap).

- **CPUID hypervisor concealment**
  The CPUID intercept serves concealment: on taken-over cores, `Fn8000_0001 ECX` reports the SVM bit **cleared** (the self-consistent "firmware-disabled" form, matching the VM_CR SVMDIS+LOCK read forge), CPUID leaves that carry no CPUID-authentic signature return zeroed values, and max-leaf is never shrunken (true values — no suspicious truncation). Verified in three steps on physical hardware (v0.9ba): low-dose smoke run clean; 30-min × 2 three-factor load rounds with 1,015 real CPUID exits handled in total (512 + 503), zero anomalies and zero DWM crashes; an all-core session of 3,003 s with Task Manager reporting *Virtualization: Disabled* on every core, plus a clean 12-core unload verified in the same campaign. Scope: the disguise is consistent exactly on the taken-over core set — with a partial takeover the bare cores answer truth, so the full-core form is the only complete disguise.

- **NPT self-concealment**
  After takeover the engine remaps its own page-table pages (~2,100 pages) to a zero page in the guest's view — the entire nested-paging hierarchy that betrays the hypervisor's presence reads back as zeros to any guest-side scanner, with no exit in steady state. Installation runs on the launch thread before the first core enters the guest (pure root mode, physical access immune), later dynamic writes go through the `vmmcall` root primitive.

- **TSC timeline compensation**
  Every VM-exit burns cycles the guest can measure with RDTSC pairs. The engine maintains a TSC-offset watermark: exit paths account for their own cost and the offset is clamped cross-core so no core's guest timeline ever runs *ahead* of real time — timing-based hypervisor detection sees a uniformly slowed clock, never a negative delta.

- **Two-tier BSOD black box + per-core DPC sentinel**
  Debug builds carry two crash-forensics layers: the classic write-stall watchdog (bugcheck 0xDEADC0DE with the last 20 log lines embedded in the bugcheck parameters) and the **DPC sentinel** — a per-core DPC heartbeat checked by the logger thread; a core that stops answering DPCs for 12 s is confirmed wedged and the system is deliberately bugchecked (0xDEADC1DE, hung-core mask as parameter) while the surviving cores can still write the dump. You get the full scene of the hang, not a frozen silent death.

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

## 🖥️ Platform Boundaries

Read this before running a bare-metal hypervisor on AMD hardware.

**The sub-SMM killer (silent hardware reset).** On some AMD mobile platforms (observed: Cezanne / Zen 3 with EOL OEM firmware), a sparse external event below SMM (likely SMU/EC class) silently resets the machine while all cores are guest-parked. Signature: hardware reset with no bugcheck, no WHEA record, no log precursor; the engine can be killed mid-load or even mid-unload, and a machine can reset ~8 seconds after a warm reboot with no driver loaded at all (a self-sustaining reset loop with decreasing intervals). It is not fixable in software: `HWCR.SMMLOCK=1` blocks SMI interception (the only OS-level observation path), making the killer invisible to both the OS and the VMM.

**Dose-sensitive desktop platforms (observed: AM5 / Zen 5 desktop).** A second failure family appeared on desktop hardware (Ryzen 5 9600X, current BIOS) that behaves like a *consumable budget* tied to SVM residency: all-core sessions die after a time that shrinks as the budget is consumed — as a silent reset, or occasionally as a CLOCK_WATCHDOG_TIMEOUT (0x101) with a core wedged and no longer servicing interrupts (both outward forms of the same event). The budget is **not** reset by the crash itself; it recovers only with minutes-to-hours of non-residency, while low-dose builds (e.g. 2 of 12 cores taken over) stay healthy through full test suites. Ruled out experimentally: C-state depth (pinning all cores to C0 changed nothing), load level (idle sessions die while sessions absorbing 14,000+ CPUID exits survive), specific applications, and every software-visible observation surface (zero WHEA events, zero log precursors, `SMMLOCK=1`). Publicly documented siblings of this family exist — no-log host resets correlating with SVM/nested-virtualization usage on AM5 KVM servers. Leading hypothesis (unproven): a firmware-autonomous watchdog (SMU/MP1 class) whose expectations are broken by all-core SVM residency. **Measured mitigations:** dose control (build with a lower core-takeover count) and session-length control (a clean unload followed by a restart was observed to start a fresh healthy session); C-state and power-plan tuning is explicitly *not* effective. On such a platform, use a low-dose build for daily work and reserve all-core sessions for short verification bursts after a cold boot.

**Operational discipline on affected platforms.** Cold machine + load late after boot + default power plan + short bursts: finish verification and unload within ~2 minutes, stop immediately after, never re-test right after a death (that is when the reset loop is hottest). A cold first run after overnight power-off is the most stable window observed (up to 40 minutes on the mobile platform); warm-machine all-core runs live in the tens-of-seconds to minutes range with no pattern.

**Hardware feature boundaries (probed at runtime, reported in the log banner).**
- **PMC/IBS virtualization** (`Fn8000_000A EDX bit8/bit26`): absent on some Zen 3 consumer APUs. Without it, the PMU side channel (guest performance counters also count root-resident instructions) cannot be closed in hardware on such platforms. LBR virtualization is present and enabled where the CPUID bit exists.
- **TSC_DEADLINE translation** (`MSR 0x6E0`): enabled only when the LAPIC actually runs in TSC-deadline mode (probed at boot; legacy-LAPIC platforms pass accesses through untouched, which is bare-metal-equivalent). Root-mode code must never access mode-dependent MSRs without a prior bare-metal probe — an illegal MSR access inside a #VMEXIT handler is a physical fault with no SEH protection.
- **STGI passthrough**: gated on the SKINIT CPUID bit — where the bit is present, a bare-metal STGI executes silently, so injecting #UD would be a detectable deviation; where absent, it stays intercepted.

**Hardware selection guidance.** Check the firmware update pipeline before adopting a platform: AMD microcode reaches consumers only through BIOS/AGESA updates from the OEM (Intel microcode ships via Windows Update; AMD does not). A laptop whose OEM has stopped BIOS updates is a hard risk for any bare-metal hypervisor — errata and power-management fixes released after EOL never reach the machine. Prefer platforms with an active AGESA cadence (desktop boards historically stay updated for years), and verify `SMMLOCK` early if SMI interception is part of your design.

## 🧪 Capability Verification Matrix

Core paths verified on nested AMD SVM (VMware guest, Windows 10 x64) — base engine at v0.3c (2-core), single-step & stealth suite at v0.7d (4-core); physical-hardware rows follow:

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

Physical-hardware verification (Ryzen 7 5800H, Windows 10 22H2, all 16 cores):

| Capability | Measured evidence |
|---|---|
| All-core takeover + clean unload on 16 cores | repeated across versions; unload leaves SVME read-back = 0 on every core, zero leaked cores, NPT accounting exact (even mid-death unload verified once: system dying of an unrelated power-policy stress, driver still tore down 16 cores cleanly) |
| Steady-state zero-exit interception (physical) | 4.6M+ ordinary-mode trigger hits (two rounds), NPF counter pinned per-core |
| TRANSPARENT mode evolution (physical) | v0.7d single-step window chain (P=0 dance form) → v0.9by onward **DR0-3 linear-address execution-breakpoint entry trap**: original page stays identity-mapped so read/write transparency is structural, exactly 1 exit per call, no page-heat constraint — the dance-specific install-time heat probe and runtime tstorm shed defenses retired together with the mechanism |
| Runtime artifact concealment (S2) | CodePage identity PTEs remapped to the zero page across both NPT views; Remove via root memcpy with PFN-reuse guard; TRANSPARENT (DR) and normal mode co-resident on the same machine (orthogonal mechanisms, distinct targets) |
| NPT self-concealment (physical) | 2,284 page-table pages remapped to a zero page; PatchGuard-runs-clean soak verified |
| MSR interception (physical) | LSTAR read forge + self-trigger thread ×3 verified per session |
| Stability under adversarial power policy | full-feature rounds: deep-idle round 30 min green, **C0-pinned round 30 min green** (historically 3/3 dead before the root-cause fix below) |
| Root-caused & fixed: the three-body race | 11-round isolation matrix (single-factor/dual-factor/combination builds) pinned CLOCK_WATCHDOG_TIMEOUT (0x101) deaths on a hardware-level race between **NPT self-concealment (remapped PT pages) × MSRPM read interception × passthrough WRMSR**: write-passthrough died in 107 s, write-intercepted (root re-executes the write) green — one-variable life/death flip, fix verified by the full accelerated suite (both rounds green, C-round first-ever pass) |
| Self-consistent "SVM inactive" story | second instance self-rejects in seconds via forged VM_CR (SVMDIS+LOCK read forge); SVM instruction family #UD injection with #GP surgery (RIP byte family check, faithful reinjection of natural #GP); 0xB8 virtualization group strictly feature-gated |
| Runtime artifact concealment (S2) | CodePage identity PTEs remapped to the zero page across all four NPT views; Remove via root memcpy with PFN-reuse guard; mixed EPT/NPT-driver installs rejected fail-loud |
| STGI passthrough gating (v0.9ar) | SKINIT CPUID bit present → STGI not intercepted, executes silently = bare-metal equivalent (r84 exit count = 0); bit absent → stays intercepted with #UD |
| TSC_DEADLINE mode gating (v0.9ar) | boot-time bare-metal probe: legacy-LAPIC host passes 0x6E0 through untouched (banner reports the exception code); the translation path engages only when the LAPIC actually runs in TSC-deadline mode — root code never touches an unprobed, mode-dependent MSR |
| Sleep-wake honest reporting (v0.9ar) | T1 heartbeats detect a biased/unbiased clock split > 10 s → honest log line on wake; no automatic re-takeover |
| Clean unload after the full v0.9ar feature set | 16-core de-virtualization (SVME read-back = 0 × 16), zero leaked cores, NPT pages fully released, S1 account closed (probe traffic exact) |

Second physical platform (Ryzen 5 9600X, AM5, Windows 10 19045):

| Capability | Measured evidence |
|---|---|
| CPUID hypervisor concealment (v0.9ba) | three-step graduation: low-dose smoke clean; 30-min × 2 three-factor accelerated load rounds all green (1,015 CPUID exits handled in total — 512 + 503 — zero anomalies, zero DWM crashes, clean unload ×2); all-core session 3,003 s with Task Manager reporting *Virtualization: Disabled* on all cores, plus a clean 12-core unload verified in the same campaign |
| Debug-subsystem fidelity (v0.9ce) | four on-machine probes green: TF single-step delivered (STATUS_SINGLE_STEP), self-set DR0 breakpoint delivered at the entry, DR readback exact (DR0 = written address, DR7 = 0x401 incl. bit10 RA1), int1 software trap delivered through the residual-#DB discriminator — the classic ICEBP hypervisor probe closes; LBR virtualization restored (root-resident branches never leak into the guest LBR stack) |
| Low-dose engine stability (dose-sensitive platform) | 2-of-12-core builds healthy through repeated multi-minute sessions and full 30-min accelerated suites on a platform where all-core sessions die within minutes |
| Dose-model characterization | all-core lifetime vs recovery-time gradient measured across sessions (15 s → 3,003 s); C-state pinning proven ineffective; load level proven irrelevant (idle dies, 14,000+ exit bursts survive) |

The stability story is kept as internal case law (not part of the repository); every claim above has a log-level evidence chain. Platform-specific hazards (the sub-SMM silent-reset killer, dose-sensitive desktop platforms, feature-absent PMU virtualization) are documented in **Platform Boundaries** above.

## ⚠️ Project Status

Milestones M0–M5 (engine, dual-NPT hook, TF+#DB single-step primitives, TRANSPARENT suite), M6 (TSC timeline compensation + clock-domain investigation), M7 (MSR hook face via MSRPM bitmaps), M8 (NPT self-concealment + the stability campaign), M9 (three-body race root-caused and fixed), M10 (CPUID interception verdict) and M11 (self-consistent story, artifact concealment + API closure, TSC_DEADLINE gating, PMU boundary study, and a full platform-hazard characterization — see **Platform Boundaries**) have all graduated **on physical hardware** (Ryzen 7 5800H). M12 (second-platform killer characterization: the dose model, its recovery behavior, and the dual outward forms) and M13 (CPUID concealment promoted to a shipping feature, verified in three steps on Ryzen 5 9600X) graduated on the second physical platform. M14 closed the four-entity death forensics (including the PatchGuard 0x109 conviction and the op-cache stale-decode fix), M15 re-based TRANSPARENT on the DR execution-breakpoint machinery (structural read/write transparency, exactly 1 exit per call), shrank the NPT views from four to two, and confined every observation probe to Debug builds (Release = pure engine lifecycle); M15.4 triaged the published detection literature vector-by-vector (attribution-denial standard: real vectors hardened, phantom vectors rejected) and closed the debug-fidelity surface — faithful int1/ICEBP delivery, probe-time yield with resume-flag, restored LBR virtualization, architectural DR readback — all verified by four on-machine probes. Current build: v0.9ce. The framework remains research-grade: a hypervisor-level bug may still bugcheck the system — always test on a disposable machine.

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

- **License is GPL-3.0 only — no commercial exceptions.**
This project is offered under the terms of the GPL-3.0 (see LICENSE),
and every use must comply with that license in full. What GPL requires —
source availability and the same license for derivatives — is exactly
what it means to use this project. Commercial use that cannot accept
GPL terms does not have the author's authorization: the author does not
offer, and will not negotiate, dual licensing, commercial exceptions,
or proprietary redistribution. Reselling this project for profit while
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

If you find this project helpful, or if you recognize its value in technical research, consider giving it a ⭐ on GitHub.

Your support helps more people discover this project, and also lets the author feel the significance of continued maintenance.

Thank you for your recognition.
