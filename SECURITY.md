# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| main    | ✓        |

## Reporting a Vulnerability

**Please use private channels only — do not open a public issue for
security reports.**

Include: affected file/function, build configuration (Debug/Release),
CPU model and Windows version, reproduction steps, and expected vs
actual behavior. A proof-of-concept is welcome but not required.

- Response target: within 7 days
- If the vulnerability is accepted, you will be credited in the
  advisory (unless you prefer to remain anonymous)
- If it is declined, a written explanation will be provided

## Scope — What Counts as a Vulnerability

This project is a **dual-use research framework**: by design it hides
its own presence from the guest OS and intercepts kernel functions.
The following are therefore **in scope**:

- Memory-safety defects in the NPT/VMCB management code (use-after-free,
  double-free, out-of-bounds access in nested-page-table handling)
- Race conditions in per-core SVM start/stop or hook install/remove
  paths that can bugcheck the system or corrupt state
- Failures of the framework's own safety invariants: hooks that leak
  (not removed cleanly), view-switch inconsistencies between cores,
  trampoline relocation errors affecting the original function
- Leaks of the TRANSPARENT-mode single-step machinery that surface a
  guest-visible #DB or leave a view window open after a fault
- Weaknesses that allow the framework's concealment guarantees to be
  broken *from the guest* by means the framework itself claims to cover

## Out of Scope — By-Design Behavior

- **The framework hides itself from the guest and its detection is not
  a vulnerability.** Being discovered by an EDR, anti-cheat, or
  researcher using means outside the documented concealment surface is
  an arms race, not a security bug.
- **Using the framework to build stealthy or malicious software is
  dual-use misuse, not a vulnerability.** The API does what it is
  documented to do.
- **Normal mode on PatchGuard-covered targets leading to a 0x109
  bugcheck is documented behavior** with a documented alternative
  (TRANSPARENT mode, low-traffic targets only), not a vulnerability.
- Hardening gaps on CPUs or Windows versions outside the documented
  requirements (AMD SVM + NPT, Win10/11 x64)
- Bugchecks caused by a caller violating the documented callback
  contract (IRQL discipline, target-resolution responsibility,
  calling conventions)
- Vulnerabilities in code that uses this framework — report them to
  the respective project, not here
