// hv_msr_contract.h — Authoritative MSR intercept/passthrough contract.
//
// This is the single place both trees and the unit test agree on which MSRs are
// intercepted and which are deliberately passed through. Changing interceptions
// must go through this file; tools/unit/hvmsr_test.c asserts the live bitmap
// matches this list.
//
// Included by:
//   HvDrv/hv_vmx.c     — FillMsrBitmap() uses these lists to set bitmap bits
//   HvEfi/hv_vmcs.c    — same
//   tools/unit/hvmsr_test.c — off-target test drives the same bitmap logic
//
// MSR index layout (Intel SDM Vol 3, 24.6.9):
//   Bytes    0–1023: Read  bitmap for MSRs 0x00000000–0x00001FFF
//   Bytes 1024–2047: Read  bitmap for MSRs 0xC0000000–0xC0001FFF
//   Bytes 2048–3071: Write bitmap for MSRs 0x00000000–0x00001FFF
//   Bytes 3072–4095: Write bitmap for MSRs 0xC0000000–0xC0001FFF
// Only the 0x00000000–0x00001FFF low range is used here; all intercepted MSRs
// are in that range.

#pragma once

// ── Intercepted MSRs ───────────────────────────────────────────────────────
// Each entry: {address, intercept_read, intercept_write}
// Rationale must be documented for each interception.

// IA32_FEATURE_CONTROL (0x3A): intercepted R+W so the exit handler can
// report VMX as present-but-disabled, hiding the running hypervisor from
// any guest RDMSR probe of this register.
//
// TREE DIVERGENCE — LOCK bit policy:
//   WDK tree (HvDrv): does NOT write FEATURE_CONTROL at driver load time.
//     The driver requires the firmware to have set the LOCK+VMXON_OUTSIDE bits
//     before the driver runs. If the MSR is unlocked, HvVmxEnable() fails.
//
//   EFI tree (HvEfi): writes FEATURE_CONTROL in VirtualizeCpuCallback
//     (hv_efi_smp.c) to set LOCK+VMXON_OUTSIDE before VMXON. This is required
//     because the EFI DXE driver runs before any OS firmware lock. The write
//     latches VT-x at the machine level (the LOCK bit is persistent across
//     reboots on many platforms). The guest still reads a virtualised
//     FEATURE_CONTROL (LOCKED only) so its view remains self-consistent.
//
//   The exit handler (hv_exit.c) returns LOCKED-only for RDMSR on this address
//   from both trees — the guest never observes VMXON_OUTSIDE being set.
#define HV_MSR_INTERCEPT_IA32_FEATURE_CONTROL  0x3A

// ── Deliberate non-interceptions ─────────────────────────────────────────
// Listed here so future changes have to consciously remove the entry rather
// than silently start intercepting. The reason is part of the contract.

// IA32_TSC_ADJUST (0x3B): the architecture adds this value to every later
// RDTSC result. Intercepting it creates a two-instruction hypervisor test:
// the guest writes it (VM-exit → we acknowledge), then reads RDTSC — if
// the hardware did not apply the write, the result is wrong. Passing it
// straight through lets hardware apply it correctly with no VM-exit.
#define HV_MSR_PASSTHROUGH_IA32_TSC_ADJUST     0x3B

// IA32_DEBUGCTL (0x1D9): shadowing it would prevent LBR (Last Branch Record)
// from working, which is itself detectable. Passed through so LBR behaves
// identically to bare metal.
#define HV_MSR_PASSTHROUGH_IA32_DEBUGCTL       0x1D9

// VMX capability MSRs (0x480–0x493): read-only; RDMSR already returns the
// real value, WRMSR already #GPs. No trap needed. Trapping adds a per-access
// VM-exit cost and a timing signature for no benefit.
#define HV_MSR_PASSTHROUGH_VMX_RANGE_LO        0x480
#define HV_MSR_PASSTHROUGH_VMX_RANGE_HI        0x493

// Performance/frequency MSRs: the PMU is not touched across VM exits (the
// PERF_GLOBAL_CTRL load/save controls are deliberately clear). Trapping
// adds timing noise and PMU breakage for no benefit.
// 0xE7 = IA32_MPERF, 0xE8 = IA32_APERF, 0x186-0x189 = IA32_PERFEVTSELx,
// 0x38F = IA32_PERF_GLOBAL_CTRL.

// ── Intercepted MSR list (table-driven; used by FillMsrBitmap) ───────────
// Add new intercepted MSRs here; each must be in the low range 0x0000–0x1FFF.
// FillMsrBitmap() iterates this list to build the bitmap — no hardcoded addresses
// anywhere else.
#define HV_INTERCEPTED_MSRS  HV_MSR_INTERCEPT_IA32_FEATURE_CONTROL

// ── Compile-time range assertions ─────────────────────────────────────────
// All intercepted MSRs must sit in the low-range bitmap zone.
#if HV_MSR_INTERCEPT_IA32_FEATURE_CONTROL > 0x1FFF
#error "HV_MSR_INTERCEPT_IA32_FEATURE_CONTROL out of low-range MSR bitmap zone"
#endif

// ── Helpers for FillMsrBitmap (used in both hv_vmx.c and hvmsr_test.c) ───
// Not directly using the macro variants above to keep the bitmap fill code
// readable; the test verifies both that the intercepted MSR is set AND that
// the passthrough MSRs are clear, using these constants.
