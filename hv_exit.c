// hv_exit.c - VM-exit handler (shared design with HvDrv/hv_exit.c).
//
// This file tracks HvDrv/hv_exit.c handler-for-handler. It uses only MSVC
// intrinsics and types from hvdefs.h — no OS-specific APIs. If a handler
// exists in the WDK tree it must exist here too: the two trees program the
// same VMCS controls, so any exit the WDK build can see, this build can see.

#include "hvdefs.h"
// Pure EPT-violation decision, shared with HvDrv/hv_exit.c and unit-tested by
// tools/unit/hv_ept_decision_test.c. Included here rather than duplicated so
// the branch whose wrong answer is a hard hang exists exactly once.
#include "../hv_ept_decision.h"
#include "../hv_ept_gen.h"    // HvEptGenerationSync / HvEptPublishMutation
#include "../hv_hookpool.h"   // HvHookTagMake / HvHookTagSlot / HvHookTagMatches

// ── Advance guest RIP past the faulting instruction ─────────────────────────

static void AdvanceGuestRip(void) {
  UINT64 rip = 0, len = 0;
  __vmx_vmread(VMCS_GUEST_RIP, &rip);
  __vmx_vmread(VMCS_EXIT_INSTR_LENGTH, &len);
  __vmx_vmwrite(VMCS_GUEST_RIP, rip + len);
}

// ── Mark this CPU as devirtualized (Pass 94) ─────────────────────────────────
//
// Every FALSE return from HvExitHandler means the assembly stub is about to
// VMXOFF and resume the guest natively. It cannot record that in the VCPU
// struct: at that point the stub runs on the host stack with guest state still
// in the VMCS, and it has no reason to know which VCPU slot it came from.
//
// Leaving Launched set was therefore a latent brick. DevirtualizeCpuCallback
// reads that flag to decide whether to issue the authenticated UNLOAD VMCALL,
// and on a CPU that already executed VMXOFF the VMCALL runs in VMX ROOT mode,
// raises #UD, and - in DXE - dead-loops with no recovery. That is reachable
// from the dispatcher's default branch, i.e. from any exit reason this build
// does not model.
//
// So the record is made HERE, while we are still in ordinary C with the VCPU
// pointer in hand. The function returns FALSE so every call site reads
// `return HvDevirtualizeThisCpu(...)` and cannot forget the return value.
//
// `vcpu` may be NULL: HvGetCurrentVcpu() returns NULL for a CPU whose APIC ID
// matches no recorded VCPU, and that case has no struct to write. It is counted
// globally instead, because silently devirtualizing an unidentified CPU is
// exactly the failure this whole change is about.
//
// Post-EBS behaviour (Open Issue 2 in STATUS.md): the asm shutdown path routes
// through HvAsmSwitchToGuest, which fetches instructions after the mov cr3
// switch to guest tables - a VA the guest's page tables don't map, so the next
// fetch #PFs with no handler and triple-faults the machine. Pre-EBS the guest
// IS the firmware whose identity map covers the stub, so that path is safe;
// post-EBS it is not, and devirtualizing turns a controllable brick ("one
// unknown exit on one CPU") into an uncontrollable one ("whole system reset").
//
// The post-EBS rule is therefore: do NOT run the asm devirt stub. Record the
// cause, inject #UD(0) into the guest so the architectural event surfaces
// (Windows bugchecks with a stack trace, VM shows a dump), and return TRUE so
// the exit handler resumes guest execution normally. That trades a hard reset
// for a diagnosable bugcheck - every observable outcome is strictly better.
static BOOLEAN HvDevirtualizeThisCpu(PVCPU vcpu, UINT32 cause)
{
  // Post-EBS short-circuit (Open Issue 2 in STATUS.md). Decide this first so
  // the vcpu->Launched/VmxEnabled flags stay consistent with reality - the
  // CPU is still in VMX non-root when we take this branch, and clearing those
  // flags would mislead any later diagnostic that reads them.
  BOOLEAN postEbs = (g_Mailbox != NULL) && HvMailboxValid(g_Mailbox) &&
                    ((HvMailboxFlags(g_Mailbox) & HV_MAILBOX_FLAG_EBS_OK) != 0);

  if (vcpu != NULL) {
    if (!postEbs) {
      // Real devirt: the asm stub is about to VMXOFF. Record that fact.
      vcpu->Launched = FALSE;
      vcpu->VmxEnabled = FALSE;
    }
    // DevirtCause is recorded on both paths - the diagnostic value of "the
    // HV wanted to devirt this CPU for reason X" doesn't change with EBS.
    vcpu->DevirtCause = cause;
  } else {
    g_Hv.DevirtNoVcpuCount++;
  }
  // Plain increment, not an atomic: this counter is diagnostic, and a lost
  // update under a concurrent devirtualize costs one count, not correctness.
  // InterlockedIncrement64 is not available in a non-DBG build of this tree
  // (the WDK syntax stub maps only InterlockedIncrement, and casting a LONG64
  // to `volatile long *` would truncate it). The flags cleared above are what
  // actually prevent the #UD; this number only lets a half-devirtualized
  // machine be recognised afterwards.
  g_Hv.DevirtCount++;

  if (g_Mailbox != NULL && HvMailboxValid(g_Mailbox)) {
    g_Mailbox->DevirtCount++;
    g_Mailbox->DevirtCause = cause;

    UINT64 exitReason = 0, qual = 0, rip = 0, rsp = 0, cr0 = 0, cr4 = 0, efer = 0;
    __vmx_vmread(VMCS_EXIT_REASON, &exitReason);
    __vmx_vmread(VMCS_EXIT_QUALIFICATION, &qual);
    __vmx_vmread(VMCS_GUEST_RIP, &rip);
    __vmx_vmread(VMCS_GUEST_RSP, &rsp);
    __vmx_vmread(VMCS_GUEST_CR0, &cr0);
    __vmx_vmread(VMCS_GUEST_CR4, &cr4);
    __vmx_vmread(VMCS_GUEST_EFER, &efer);

    g_Mailbox->DevirtExitReason   = (UINT32)exitReason;
    g_Mailbox->DevirtExitQualLow  = (UINT32)qual;
    g_Mailbox->DevirtExitQualHigh = (UINT32)(qual >> 32);
    g_Mailbox->DevirtGuestRipLow  = (UINT32)rip;
    g_Mailbox->DevirtGuestRipHigh = (UINT32)(rip >> 32);
    g_Mailbox->DevirtGuestRspLow  = (UINT32)rsp;
    g_Mailbox->DevirtGuestRspHigh = (UINT32)(rsp >> 32);
    g_Mailbox->DevirtGuestCr0Low  = (UINT32)cr0;
    g_Mailbox->DevirtGuestCr0High = (UINT32)(cr0 >> 32);
    g_Mailbox->DevirtGuestCr4Low  = (UINT32)cr4;
    g_Mailbox->DevirtGuestCr4High = (UINT32)(cr4 >> 32);
    g_Mailbox->DevirtGuestEferLow = (UINT32)efer;
    g_Mailbox->DevirtGuestEferHigh = (UINT32)(efer >> 32);

    if (vcpu != NULL) {
      g_Mailbox->DevirtCpuIndex = vcpu->ProcessorIndex;
      g_Mailbox->DevirtApicId   = vcpu->ApicId;
    } else {
      g_Mailbox->DevirtCpuIndex = 0xFFFFFFFFu;
      int apicRegs[4] = {0};
      __cpuid(apicRegs, 1);
      g_Mailbox->DevirtApicId   = (UINT32)((apicRegs[1] >> 24) & 0xFF);
    }
  }

  // Post-EBS: inject #UD rather than running the asm devirt stub. See the
  // header comment on this function for why the stub triple-faults post-EBS,
  // and why #UD is strictly better than the alternative.
  if (postEbs) {
    UINT64 alreadyInjected = 0;
    __vmx_vmread(VMCS_ENTRY_INTERRUPTION_INFO, &alreadyInjected);
    if (!(alreadyInjected & (1ULL << 31))) {
      // #UD: vector 6, type 3 (hardware exception), no error code, valid=1.
      // The SDM makes VMCS_EXIT_INSTR_LENGTH valid for every exit reason that
      // reaches this helper (CPUID, VMCALL, CR access, MSR access, invalid
      // guest state, MCE, MSR loading); the triple-fault case has no valid
      // length but injection on top of a triple fault is moot. Copying the
      // live field is correct where it is live and inert where it is not.
      __vmx_vmwrite(VMCS_ENTRY_EXCEPTION_ERROR, 0);
      __vmx_vmwrite(VMCS_ENTRY_INTERRUPTION_INFO,
                    6ULL | (3ULL << 8) | (1ULL << 31));
      UINT64 len = 0;
      __vmx_vmread(VMCS_EXIT_INSTR_LENGTH, &len);
      __vmx_vmwrite(VMCS_ENTRY_INSTR_LENGTH, len);
    }
    // If an injection was ALREADY written (HandleNmi, HandleExternalInterrupt,
    // or an EPT handler all can do that), leave it in place: the pre-existing
    // injection is what the exit's own semantics asked for, and clobbering it
    // with #UD would mask a real event. The TRUE return still skips the
    // asm shutdown path, which is the only part that would brick the machine.
    return TRUE;
  }

  return FALSE;
}

// ── CPUID handler ───────────────────────────────────────────────────────────

static void HvCpuidLookup(PVCPU vcpu, UINT32 leaf, UINT32 subleaf,
                          UINT32 out[4]) {
  UINT32 slot = (leaf ^ (subleaf * 2654435761u)) & (HV_CPUID_CACHE_SIZE - 1);
  HV_CPUID_CACHE_ENTRY *ce = &vcpu->CpuidCache[slot];

  if (ce->Valid && ce->Leaf == leaf && ce->SubLeaf == subleaf) {
    out[0] = ce->Regs[0];
    out[1] = ce->Regs[1];
    out[2] = ce->Regs[2];
    out[3] = ce->Regs[3];
    return;
  }

  int r[4] = {0, 0, 0, 0};
  __cpuidex(r, (int)leaf, (int)subleaf);
  out[0] = (UINT32)r[0];
  out[1] = (UINT32)r[1];
  out[2] = (UINT32)r[2];
  out[3] = (UINT32)r[3];

  ce->Leaf = leaf;
  ce->SubLeaf = subleaf;
  ce->Valid = 1;
  ce->Regs[0] = out[0];
  ce->Regs[1] = out[1];
  ce->Regs[2] = out[2];
  ce->Regs[3] = out[3];
}

// ── CPUID timing-pad calibration ────────────────────────────────────────────
//
// See hvdefs.h. Runs once on the boot CPU before any VMXON, so the samples are
// genuinely unvirtualized and AP bring-up is untouched. The result is a p99
// floor plus a spread-derived jitter margin; an implausible (or absent)
// measurement leaves the historical 200/0 fallback in place.
void HvCalibrateCpuidLatency(void) {
  g_Hv.CpuidPadTarget = HV_CPUID_PAD_DEFAULT_TARGET;
  g_Hv.CpuidPadJitter = HV_CPUID_PAD_DEFAULT_JITTER;
  g_Hv.CpuidPadP50 = 0;   // 0 = "no measurement", see HV_HYPERCALL_QUERY_CPID_PAD
  g_Hv.CpuidPadP99 = 0;

  int r[4];
  for (UINT32 i = 0; i < 32; i++)
    __cpuidex(r, 0, 0);   // settle caches / branch predictor before sampling

  UINT64 samples[HV_CPUID_PAD_SAMPLES];
  for (UINT32 i = 0; i < HV_CPUID_PAD_SAMPLES; i++) {
    UINT64 t0 = __rdtsc();
    __cpuidex(r, 0, 0);
    UINT64 t1 = __rdtsc();
    samples[i] = (t1 > t0) ? (t1 - t0) : 0;
  }

  // Insertion sort: HV_CPUID_PAD_SAMPLES is small and this runs once.
  for (UINT32 i = 1; i < HV_CPUID_PAD_SAMPLES; i++) {
    UINT64 v = samples[i];
    UINT32 j = i;
    while (j > 0 && samples[j - 1] > v) {
      samples[j] = samples[j - 1];
      j--;
    }
    samples[j] = v;
  }

  UINT64 p50 = samples[HV_CPUID_PAD_SAMPLES / 2];
  UINT64 p99 = samples[(HV_CPUID_PAD_SAMPLES * 99) / 100];

  // "Implausible" means this was not bare-metal CPUID: too fast to have run
  // one at all, or slow enough that an outer hypervisor is trapping it. Keep
  // the fixed fallback rather than pad every exit to a trapped latency.
  if (p99 < HV_CPUID_PAD_MIN || p99 > HV_CPUID_PAD_MAX)
    return;

  UINT64 spread = (p99 > p50) ? (p99 - p50) : 0;
  if (spread > 64)
    spread = 64;   // a small margin is enough to break a hard floor

  g_Hv.CpuidPadTarget = (UINT32)p99;
  g_Hv.CpuidPadJitter = (UINT32)spread;
  g_Hv.CpuidPadP50 = (UINT32)p50;
  g_Hv.CpuidPadP99 = (UINT32)p99;
}

static void CpuidTimingPad(UINT64 entryTsc) {
  // Floor = the calibrated p99 (or the 200 fallback); the per-call jitter is
  // derived from the in-flight TSC so the padded latency is a range rather
  // than a hard floor. Stateless on purpose — several vCPUs run this
  // concurrently and g_Hv.CpuidPad* are read-only after calibration.
  UINT64 target = entryTsc + g_Hv.CpuidPadTarget;
  UINT32 jitter = g_Hv.CpuidPadJitter;
  if (jitter)
    target += (UINT32)(HvRandomU64() % ((UINT64)jitter + 1));
  while (__rdtsc() < target)
    _mm_pause();
}

static BOOLEAN HandleCpuid(PVCPU vcpu, PGUEST_REGS regs) {
  UINT64 entryTsc = __rdtsc();

  UINT32 leaf = (UINT32)regs->Rax;
  UINT32 subleaf = (UINT32)regs->Rcx;
  UINT32 out[4] = {0, 0, 0, 0};

  // Canary leaf 0x13371337: Zero-privilege Ring 3 hypervisor residency proof.
  // Bypasses ticket/VMCALL requirements and allows instant per-core verification.
  if (leaf == 0x13371337) {
    regs->Rax = 0x564D5831; // "VMX1" magic signature
    regs->Rbx = vcpu ? (UINT64)vcpu->ProcessorIndex : 0xFFFFFFFFULL;
    regs->Rcx = (UINT64)g_Hv.ExitLogIndex;
    regs->Rdx = (UINT64)g_Hv.VcpuCount;
    AdvanceGuestRip();
    return TRUE;
  }

  // Every leaf — including the 0x40000000 hypervisor range — is answered by
  // running real CPUID and memoising it. A bare-metal CPU returns the highest
  // standard leaf's data for every out-of-range leaf, so all extended leaves
  // must agree. The old code synthesised (maxleaf,0,0,0) for 0x40000000 — a
  // response no CPU ever returns, exactly what hvdetect cross-leaf checks catch.
  HvCpuidLookup(vcpu, leaf, subleaf, out);

  if (leaf == 1) {
    // ECX.5 (VMX) is deliberately LEFT SET. Clearing it on a VMX-capable CPU
    // is self-contradictory and is paired with FEATURE_CONTROL returning
    // "firmware-disabled" — the coherent story hardware already tells.
    out[2] &= ~(1u << 31);   // hypervisor present
    out[3] &= ~(1u << 31);   // EDX.31 (some older CPUs)
  }

  regs->Rax = out[0];
  regs->Rbx = out[1];
  regs->Rcx = out[2];
  regs->Rdx = out[3];

  CpuidTimingPad(entryTsc);
  AdvanceGuestRip();
  return TRUE;
}

// ── NMI handler ─────────────────────────────────────────────────────────────

static void HandleNmi(void) {
  UINT64 exitIntInfo = 0;
  __vmx_vmread(VMCS_EXIT_INTERRUPTION_INFO, &exitIntInfo);

  UINT32 vector = (UINT32)(exitIntInfo & 0xFF);
  UINT32 type = (UINT32)((exitIntInfo >> 8) & 7);

  // If an IDT-vectoring event was in flight when this exit occurred (SDM
  // Vol 3C §27.2.4), the generic re-inject block at the end of HvExitHandler
  // will put it back; writing an NMI injection here would clobber that. The
  // original event is architecturally higher priority than our re-injected
  // NMI, so defer. Dropping an NMI once is finite; corrupting an in-flight
  // exception is not.
  UINT64 idtInfo = 0;
  __vmx_vmread(VMCS_IDT_VECTORING_INFO, &idtInfo);
  if (idtInfo & (1ULL << 31)) return;

  if (vector == 2 && type == 2) {
    UINT64 injectInfo = 2 | (2ULL << 8) | (1ULL << 31);
    __vmx_vmwrite(VMCS_ENTRY_INTERRUPTION_INFO, injectInfo);
  }
}

// ── External interrupt handler ──────────────────────────────────────────────
//
// Reached only when PIN_BASED_EXT_INT_EXIT is set, which the Raptor Lake FIXED0
// bits force on whether or not we requested it. With EXIT_CTRL_ACK_INT_ON_EXIT
// enabled (hv_vmcs.c), the CPU acknowledges the interrupt on exit and leaves
// the vector in VMCS_EXIT_INTERRUPTION_INFO. The host IDT only halts, so we
// re-inject the vector via VMCS_ENTRY_INTERRUPTION_INFO; the guest's own IVT /
// IDT then handles it on VM-entry. Without this re-injection the interrupt is
// silently dropped — the firmware timer tick, PS/2, USB, SATA, every IPI the
// OS loader relies on. Do NOT advance RIP: the guest didn't execute anything,
// an interrupt is an asynchronous event, so RIP must stay at the next
// instruction to execute.
//
// If ACK_INT_ON_EXIT was stripped by AdjustControls (CPU disallows it, which
// no shipping Intel CPU does), the valid-bit test below is FALSE and we
// resume without injection — the interrupt stays pending at the LAPIC and
// the guest will see it when it next clears IF, matching bare-metal behaviour
// as closely as possible given the capability.

static void HandleExternalInterrupt(void) {
  UINT64 exitIntInfo = 0;
  __vmx_vmread(VMCS_EXIT_INTERRUPTION_INFO, &exitIntInfo);

  // Bit 31 is the valid bit. ACK sets it; the control stripped away by
  // AdjustControls leaves it clear.
  if (!(exitIntInfo & (1ULL << 31))) return;

  // Defer to any IDT-vectoring event in flight (SDM §27.2.4). The generic
  // re-inject block at the end of HvExitHandler will replay it; writing an
  // injection here would clobber that in-flight exception. The architectural
  // priority is: finish the original delivery, then take the new interrupt.
  // The LAPIC has already ACKed, so this one external interrupt is lost -
  // finite loss, no corruption of in-flight state.
  UINT64 idtInfo = 0;
  __vmx_vmread(VMCS_IDT_VECTORING_INFO, &idtInfo);
  if (idtInfo & (1ULL << 31)) return;

  UINT32 vector = (UINT32)(exitIntInfo & 0xFF);
  // Build the entry-injection word: vector, type 0 (external interrupt),
  // error-code valid 0 (external interrupts never have one), valid bit 1.
  UINT64 injectInfo = (UINT64)vector | (0ULL << 8) | (1ULL << 31);
  __vmx_vmwrite(VMCS_ENTRY_INTERRUPTION_INFO, injectInfo);
}

// ── VMCALL handler ──────────────────────────────────────────────────────────

static BOOLEAN HandleVmcall(PVCPU vcpu, PGUEST_REGS regs) {
  UINT64 magic = regs->Rcx;
  UINT64 id = regs->Rdx;
  UINT64 p1 = regs->R8;
  UINT64 p2 = regs->R9;
  UINT64 p3 = regs->R10;
  UINT64 p4 = regs->R11;

  UINT64 result = HvHypercallDispatch(vcpu, magic, id, p1, p2, p3, p4);

  if (result == HV_STATUS_NOT_OURS) {
    UINT64 info = 6 | (3ULL << 8) | (1ULL << 31);
    __vmx_vmwrite(VMCS_ENTRY_INTERRUPTION_INFO, info);
    __vmx_vmwrite(VMCS_ENTRY_INSTR_LENGTH, 3);
    return TRUE;
  }

  regs->Rax = result;
  AdvanceGuestRip();

  // UNLOAD is a REQUESTED teardown, but the stub VMXOFFs this CPU exactly as an
  // involuntary one would, so the flags have to be cleared here too - otherwise
  // the same stale-Launched VMCALL hazard applies to any teardown path that does
  // not come back around to the vCPU.
  if ((UINT32)id == HV_HYPERCALL_UNLOAD && result == HV_STATUS_SUCCESS)
    return HvDevirtualizeThisCpu(vcpu, HV_DEVIRT_UNLOAD);

  return TRUE;
}

// ── XSETBV handler ──────────────────────────────────────────────────────────

static void HvInjectGp(void) {
  __vmx_vmwrite(VMCS_ENTRY_EXCEPTION_ERROR, 0);
  __vmx_vmwrite(VMCS_ENTRY_INTERRUPTION_INFO,
                13 | (3ULL << 8) | (1ULL << 11) | (1ULL << 31));
  UINT64 len = 0;
  __vmx_vmread(VMCS_EXIT_INSTR_LENGTH, &len);
  __vmx_vmwrite(VMCS_ENTRY_INSTR_LENGTH, len);
}

static void HandleXsetbv(PVCPU vcpu, PGUEST_REGS regs) {
  UINT32 index = (UINT32)regs->Rcx;
  UINT64 value = ((UINT64)(UINT32)regs->Rdx << 32) | (UINT32)regs->Rax;

  // Bare metal: XSETBV with any XCR index other than 0 #GP(0)s -
  // feign the fault rather than silently dropping the write.
  if (index != 0) {
    HvInjectGp();
    return;
  }

  // Validate BEFORE executing. _xsetbv runs in VMX root, so an invalid value
  // would raise #GP there - with no guest handler to take it - instead of
  // faulting in the guest that asked for it. CPUID.0xD:0.EAX reports the XCR0
  // bits this CPU supports; XCR0[0] (x87) is mandatory and XCR0[2] (AVX)
  // requires XCR0[1] (SSE). (Mirrors HvDrv/hv_exit.c HandleXsetbv.)
  int supportedRegs[4] = {0, 0, 0, 0};
  __cpuidex(supportedRegs, 0xD, 0);
  UINT64 supported = (UINT64)(UINT32)supportedRegs[0];

  if (!HvXcr0ValueValid(value, supported)) {
    HvInjectGp();
    return;
  }

  // Architecturally legal but unsavable here: a component this value enables
  // is larger than the exit stub's reserved save area, so its state would
  // never be saved and the handler's own SIMD use would corrupt it. The
  // guest gets the same #GP bare metal gives for an illegal XCR0 value.
  if (!HvXsaveNewBitsSavable(value)) {
    HvInjectGp();
    return;
  }

  _xsetbv(index, value);

  // XCR0 just changed, so the exit stub's save mask has to follow it. A
  // component enabled here but left out of the mask would never be saved
  // across an exit, and the C handler's own SIMD use would clobber it.
  HvRefreshStateSaveMask();

  // CPUID leaf 0xD reports XCR0-dependent state sizes: any cached entries
  // are stale now. Drop the whole cache; it repopulates on demand.
  RtlZeroMemory(vcpu->CpuidCache, sizeof(vcpu->CpuidCache));

  AdvanceGuestRip();
}

// ── EPT violation handler ───────────────────────────────────────────────────

static BOOLEAN HandleEptViolation(PVCPU vcpu) {
  UNREFERENCED_PARAMETER(vcpu);

  UINT64 qual = 0, gpa = 0, gla = 0;
  __vmx_vmread(VMCS_EXIT_QUALIFICATION, &qual);
  __vmx_vmread(VMCS_GUEST_PHYS_ADDR, &gpa);
  __vmx_vmread(VMCS_GUEST_LINEAR_ADDR, &gla);

  // ── Universal EPT violation handler ──────────────────────────────────────
  //
  // EPT violation = the EPT does not permit the attempted access at this GPA.
  // If HvEptLookup4K returns an entry, this is one of our pages (identity
  // map pages have full RWX and never violate). Grant the attempted access.
  //
  // Why we do NOT inject #PF for pages we own:
  //
  //   The EFI firmware's #PF handler cannot fix EPT restrictions — EPT is
  //   invisible to the guest. When we inject #PF for an EPT violation, the
  //   firmware's handler runs, finds the virtual address correctly mapped in
  //   its own page tables, returns without changing anything, the faulting
  //   instruction retries, hits the same EPT violation, we inject #PF
  //   again, and the machine hangs indefinitely with no keyboard response.
  //
  //   This is the brick failure mode we observed on bare-metal Dell boot.
  //   Any case that falls through to the #PF block for a page in our EPT is
  //   a latent brick. We therefore handle every variant uniformly:
  //
  //     - Decoy write: special-cased first (preserves the decoy semantics —
  //       Write=1 remains the detection signal if an observer wrote the
  //       bait page, visible via EPT_DECOY_TAG inspection by other tools).
  //     - Any other access to a page we own: grant R (always), W (if write),
  //       X (if instruction fetch). This covers reads to XWR=0 pages,
  //       follow-up writes to pages Pass 78 already made readable, and the
  //       theoretical instruction-fetch case.
  //
  //   The instruction must NOT be skipped on resume: VMCS_EXIT_INSTR_LENGTH
  //   is undefined for EPT violations (SDM Table 27-9), so the field still
  //   holds whatever a previous exit left in it; advancing RIP by it would
  //   silently drop a real guest instruction.
  //
  //   Only when HvEptLookup4K returns NULL (GPA not in our identity map —
  //   above HostPml4Units × 512GB, or a crafted GPA) do we inject #PF so
  //   the guest sees a conventional page fault.

  // EPT stealth hook: R/W on a hooked page → swap to original, enable MTF
  UINT32 hookIdx = HvEptFindHook(gpa);
  if (hookIdx != HV_HOOK_SLOT_NONE && !(qual & 4)) {
    HV_EPT_HOOK *hook = &g_Hv.EptHooks[hookIdx];
    // Live mutation, and the publish is the HvEptInvalidate() below - after the
    // swap, never before it. See the INVARIANT note in ../hv_ept_gen.h.
    hook->PtePtr->Value = hook->OrigPteValue;
    HvEptInvalidate();
    // Tag the pending restore with this slot AND this occupancy's epoch, so a
    // slot reused before the single-step arrives is refused rather than
    // restored against the wrong hook. See ../hv_hookpool.h.
    vcpu->MtfHookTag = HvHookTagMake(hookIdx, hook->Epoch);
    vcpu->MtfRestorePending = TRUE;
    SIZE_T procCtl = 0;
    __vmx_vmread(VMCS_PROC_BASED_CONTROLS, &procCtl);
    procCtl |= PROC_BASED_MONITOR_TRAP;
    __vmx_vmwrite(VMCS_PROC_BASED_CONTROLS, procCtl);
    return TRUE;
  }

  // The decision itself is a pure function in ../hv_ept_decision.h, unit-tested
  // by tools/unit/hv_ept_decision_test.c against every (qual, entry-state)
  // tuple. HvDrv/hv_exit.c calls the same function, so a regression in either
  // tree's brick-critical branch fails the off-target suite.
  // HvEptEnsure4K dynamically splits any 2MB page backing this GPA, ensuring
  // valid 4K PTE permissions can be manipulated without infinite-looping.
  EPT_PTE *entry = HvEptEnsure4K(&g_Hv.Ept, gpa);
  HV_EPT_DECISION dec = HvEptDecide(
      qual,
      entry ? 1 : 0,
      entry ? (unsigned char)(entry->Value & 7) : 0,
      entry ? ((entry->Value & EPT_DECOY_TAG) ? 1 : 0) : 0);

  // `entry` is re-checked here rather than relying on dec.handled implying
  // entryExists: every write below is a dereference in VMX root mode, where a
  // #PF has no handler and is a triple fault. The invariant holds today, and
  // this makes a future violation of it a no-op instead of a brick.
  if (dec.handled && entry) {
    if (dec.injectUd) {
      // Invariant (E): instruction fetch from decoy bait. Granting Execute
      // here would run the page's RDRAND fill as code; #PF would loop (see
      // invariant A). #UD terminates the instruction instead.
      UINT64 udInfo = 6 | (3ULL << 8) | (1ULL << 31);
      __vmx_vmwrite(VMCS_ENTRY_INTERRUPTION_INFO, udInfo);
      return TRUE;
    }
    if (dec.grantRead)    entry->Read    = 1;
    if (dec.grantWrite)   entry->Write   = 1;
    if (dec.grantExecute) entry->Execute = 1;
    HvEptInvalidate();
    return TRUE;
  }

  // Decision asked for #PF injection — no entry in our EPT.
  UINT64 info = 14 | (3ULL << 8) | (1ULL << 11) | (1ULL << 31);
  __vmx_vmwrite(VMCS_ENTRY_INTERRUPTION_INFO, info);
  UINT64 pfError = 0;
  if (qual & 2)
    pfError |= 2;
  if (qual & 4)
    pfError |= 0x10;
  UINT64 csAccess = 0;
  __vmx_vmread(VMCS_GUEST_CS_ACCESS, &csAccess);
  if ((csAccess & 3) == 3)
    pfError |= 4;
  __vmx_vmwrite(VMCS_ENTRY_EXCEPTION_ERROR, pfError);

  // Intel SDM Vol 3C §27.2.1: Bit 7 of qual indicates if Guest Linear Address is valid.
  if (qual & (1ULL << 7)) {
    HvAsmWriteCr2(gla);
  }

  return TRUE;
}

// ── MSR read/write handlers ─────────────────────────────────────────────────

static void HandleRdmsr(PVCPU vcpu, PGUEST_REGS regs) {
  UNREFERENCED_PARAMETER(vcpu);
  UINT32 msr = (UINT32)regs->Rcx;

  UINT64 val;
  switch (msr) {
  case MSR_IA32_FEATURE_CONTROL:
    val = FEATURE_CONTROL_LOCKED;
    break;

  case MSR_IA32_EFER:
    __vmx_vmread(VMCS_GUEST_EFER, &val);
    break;

  // NOTE: no 0x3B (IA32_TSC_ADJUST) case. The EFI VCPU deliberately has no
  // TscAdjust shadow (see hvdefs.h): the MSR passes through to hardware
  // untouched, so RDMSR(0x3B) reads the true hardware value via default.
  // A shadow would let a guest see a RDMSR round-trip change while RDTSC
  // stood still - a two-instruction VM test.

  default:
    // Read hardware MSR safely. If the MSR is unmodeled or invalid on this CPU,
    // HvAsmReadMsrSafe catches the host #GP without freezing root mode,
    // allowing us to inject #GP(0) into the guest matching architectural behavior.
    if (!HvAsmReadMsrSafe(msr, &val)) {
      HvInjectGp();
      return;
    }
    break;
  }

  regs->Rax = val & 0xFFFFFFFF;
  regs->Rdx = val >> 32;
  AdvanceGuestRip();
}

static void HandleWrmsr(PVCPU vcpu, PGUEST_REGS regs) {
  UNREFERENCED_PARAMETER(vcpu);
  UINT32 msr = (UINT32)regs->Rcx;
  UINT64 val = ((UINT64)(UINT32)regs->Rdx << 32) | (UINT32)regs->Rax;

  switch (msr) {
  case MSR_IA32_FEATURE_CONTROL:
    HvInjectGp();
    return;
  case MSR_IA32_VMX_BASIC:
  case MSR_IA32_VMX_PINBASED_CTLS:
  case MSR_IA32_VMX_PROCBASED_CTLS:
  case MSR_IA32_VMX_EXIT_CTLS:
  case MSR_IA32_VMX_ENTRY_CTLS:
  case MSR_IA32_VMX_MISC:
  case MSR_IA32_VMX_CR0_FIXED0:
  case MSR_IA32_VMX_CR0_FIXED1:
  case MSR_IA32_VMX_CR4_FIXED0:
  case MSR_IA32_VMX_CR4_FIXED1:
  case MSR_IA32_VMX_VMCS_ENUM:
  case MSR_IA32_VMX_PROCBASED_CTLS2:
  case MSR_IA32_VMX_EPT_VPID_CAP:
  case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
  case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
  case MSR_IA32_VMX_TRUE_EXIT_CTLS:
  case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
    HvInjectGp();
    return;
  case MSR_IA32_EFER:
    __vmx_vmwrite(VMCS_GUEST_EFER, val);
    break;
  // NOTE: no 0x3B (IA32_TSC_ADJUST) write case. It passes through to
  // hardware untouched; shadowing it here would desync RDMSR from RDTSC
  // (see the read side above).
  default:
    if (!HvAsmWriteMsrSafe(msr, val)) {
      HvInjectGp();
      return;
    }
    break;
  }
  AdvanceGuestRip();
}

// ── CR-access handler ───────────────────────────────────────────────────────
// Ported from HvDrv/hv_exit.c. CR-access exits CAN fire here: the VMCS CR4
// guest/host mask owns VMXE, so any guest write that changes CR4 bit 13
// exits. Without this handler the default case resumed the guest without
// advancing RIP — an infinite VM-exit loop (hang) on the first CR4 write
// that touched the masked bit.

static void HandleCrAccess(PVCPU vcpu, PGUEST_REGS regs) {
  UINT64 qual = 0;
  __vmx_vmread(VMCS_EXIT_QUALIFICATION, &qual);

  UINT32 cr     = (UINT32)(qual & 0xF);        // bits 3:0  - control register
  UINT32 access = (UINT32)((qual >> 4) & 0x3); // bits 5:4  - access type
  UINT32 gpr    = (UINT32)((qual >> 8) & 0xF); // bits 11:8 - GP register

  // GUEST_REGS is laid out in the same order the CR-access encoding numbers
  // GP registers (RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8..R15), so the
  // instruction's register operand indexes the save area directly - with one
  // exception: the stub reserves a placeholder for index 4 (RSP) rather than
  // saving it, so `mov crX, rsp` / `mov rsp, crX` would read or write a stale
  // slot. Read the real RSP from the VMCS guest-state area instead.
  UINT64 rspFromVmcs = 0;
  if (gpr == 4) {
    __vmx_vmread(VMCS_GUEST_RSP, &rspFromVmcs);
    ((UINT64 *)regs)[4] = rspFromVmcs;
  }
  UINT64 *gprSlot = &((UINT64 *)regs)[gpr];
  UINT64 cur = 0;

  switch (access) {
  case 0: // MOV to CR
    switch (cr) {
    case 0: {
      UINT64 oldCr0 = 0;
      __vmx_vmread(VMCS_GUEST_CR0, &oldCr0);

      UINT64 fixed0 = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
      // Unrestricted guest: PE and PG can be 0
      fixed0 &= ~(CR0_PE | CR0_PG);
      cur = (*gprSlot | fixed0) & __readmsr(MSR_IA32_VMX_CR0_FIXED1);
      HvVmWriteLog(VMCS_GUEST_CR0, cur);
      HvVmWriteLog(VMCS_CR0_READ_SHADOW, cur);

      // Track PG transitions for INIT-SIPI AP bringup (real → long mode).
      // EFER is saved by hardware on each VM exit, so VMCS_GUEST_EFER
      // reflects any guest WRMSR that set LME since the last exit.
      if (!(oldCr0 & CR0_PG) && (cur & CR0_PG)) {
        UINT64 efer = 0;
        __vmx_vmread(VMCS_GUEST_EFER, &efer);
        if (efer & EFER_LME) {
          efer |= EFER_LMA;
          __vmx_vmwrite(VMCS_GUEST_EFER, efer);
          UINT64 ec = 0;
          __vmx_vmread(VMCS_ENTRY_CONTROLS, &ec);
          __vmx_vmwrite(VMCS_ENTRY_CONTROLS,
                        ec | ENTRY_CTRL_IA32E_MODE_GUEST);
        }
      } else if ((oldCr0 & CR0_PG) && !(cur & CR0_PG)) {
        UINT64 efer = 0;
        __vmx_vmread(VMCS_GUEST_EFER, &efer);
        if (efer & EFER_LMA) {
          efer &= ~EFER_LMA;
          __vmx_vmwrite(VMCS_GUEST_EFER, efer);
          UINT64 ec = 0;
          __vmx_vmread(VMCS_ENTRY_CONTROLS, &ec);
          __vmx_vmwrite(VMCS_ENTRY_CONTROLS,
                        ec & ~(UINT64)ENTRY_CTRL_IA32E_MODE_GUEST);
        }
      }
    } break;

    case 3:
      // Bit 63 is the no-TLB-flush request (CR4.PCIDE=1 path); the VMCS
      // must receive the physical CR3 address with that bit clear.
      HvVmWriteLog(VMCS_GUEST_CR3, *gprSlot & ~(1ULL << 63));
      break;

    case 4:
      // FIXED0 already includes VMXE; forcing it again documents that a
      // guest can never clear it while we are in VMX operation. The read
      // shadow must track the new value or the guest would read stale
      // bits that are not covered by the mask.
      cur = (*gprSlot | __readmsr(MSR_IA32_VMX_CR4_FIXED0)) &
            __readmsr(MSR_IA32_VMX_CR4_FIXED1);
      cur |= CR4_VMXE;
      HvVmWriteLog(VMCS_GUEST_CR4, cur);
      HvVmWriteLog(VMCS_CR4_READ_SHADOW, cur & ~CR4_VMXE);
      break;

    case 8:
      // Emulated in vcpu->GuestCr8. __writecr8 would write the HOST's CR8
      // (the current IRQL) mid-handler; the guest's TPR lives here instead.
      // (Mirrors HvDrv/hv_exit.c.)
      vcpu->GuestCr8 = *gprSlot;
      break;

    default:
      break;
    }
    break;

  case 1: // MOV from CR
    switch (cr) {
    case 0: __vmx_vmread(VMCS_GUEST_CR0, gprSlot); break;
    case 3: __vmx_vmread(VMCS_GUEST_CR3, gprSlot); break;
    case 4:
      __vmx_vmread(VMCS_GUEST_CR4, gprSlot);
      *gprSlot &= ~CR4_VMXE;
      break;
    case 8: *gprSlot = vcpu->GuestCr8; break;
    default: break;
    }
    // MOV-from-CR with gpr==4 (`mov rsp, crX`): the value landed in the RSP
    // placeholder slot, which the exit stub never restores to a real register.
    // Write it back to the VMCS guest RSP so the guest actually sees it.
    if (gpr == 4) __vmx_vmwrite(VMCS_GUEST_RSP, ((UINT64 *)regs)[4]);
    break;

  case 2: // CLTS - clears CR0.TS and nothing else
    __vmx_vmread(VMCS_GUEST_CR0, &cur);
    cur &= ~CR0_TS;
    HvVmWriteLog(VMCS_GUEST_CR0, cur);
    HvVmWriteLog(VMCS_CR0_READ_SHADOW, cur);
    break;

  case 3: // LMSW - low 16 bits of CR0, then re-masked by the fixed bits
    {
      UINT64 src;
      if (qual & (1ULL << 6))
        src = (qual >> 16) & 0xFFFFULL;
      else
        src = *gprSlot & 0xFFFFULL;
      __vmx_vmread(VMCS_GUEST_CR0, &cur);
      cur = (cur & ~0xFFFFULL) | src;
      UINT64 fixed0 = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
      fixed0 &= ~(CR0_PE | CR0_PG); // unrestricted guest
      cur = (cur | fixed0) & __readmsr(MSR_IA32_VMX_CR0_FIXED1);
      HvVmWriteLog(VMCS_GUEST_CR0, cur);
      HvVmWriteLog(VMCS_CR0_READ_SHADOW, cur);
    }
    break;

  default:
    break;
  }

  // Always advance: an unexpected CR exit must degrade to "instruction
  // ignored", never to an exit spin.
  AdvanceGuestRip();
}

// ── Main VM-exit dispatcher ─────────────────────────────────────────────────

BOOLEAN HvExitHandler(PGUEST_REGS regs) {
  PVCPU vcpu = HvGetCurrentVcpu();
  if (!vcpu)
    return HvDevirtualizeThisCpu(NULL, HV_DEVIRT_NO_VCPU);

  // EPT coherence. This handler runs in VMX root, which is the only context in
  // which this processor may invalidate its own cached EPT translations -
  // everywhere else it is executing the guest, where INVEPT is #UD. Any
  // mutation another processor published since our last exit is applied here,
  // before any handler below looks at the EPT. Costs one load and one compare
  // when nothing changed, and no INVEPT at all. See ../hv_ept_gen.h.
  HvEptGenerationSync(vcpu);

  UINT64 exitReason = 0;
  __vmx_vmread(VMCS_EXIT_REASON, &exitReason);
  UINT32 reason = (UINT32)(exitReason & 0xFFFF);
  if (exitReason & (1ULL << 31)) {
    // Bit 31 indicates VM-entry failure (Intel SDM Vol 3C §24.9.1 / §27.1).
    if (g_Mailbox != NULL && HvMailboxValid(g_Mailbox)) {
      UINT64 instrErr = 0;
      __vmx_vmread(VMCS_VM_INSTR_ERROR, &instrErr);
      g_Mailbox->VmresumeFailCount++;
      g_Mailbox->VmresumeFailInstrErr = (UINT32)instrErr;
    }
  }
#if DBG
  // ExitCounts[64] lives inside HV_GLOBAL only in checked builds (hvdefs.h),
  // and the HV_HYPERCALL_QUERY_EXIT_COUNTS reader (hv_efi_hypercall.c) is
  // under the same guard. Without this guard the RELEASE build fails to
  // compile with "struct HV_GLOBAL has no field named 'ExitCounts'".
  if (reason < 64) InterlockedIncrement64(&g_Hv.ExitCounts[reason]);
#endif

  UINT64 rip = 0;
  __vmx_vmread(VMCS_GUEST_RIP, &rip);

  // Runtime Exit Log Ring Buffer (Pass 96)
  {
    UINT64 rsp = 0, qual = 0;
    __vmx_vmread(VMCS_GUEST_RSP, &rsp);
    __vmx_vmread(VMCS_EXIT_QUALIFICATION, &qual);
    LONG64 logIdx = InterlockedIncrement64(&g_Hv.ExitLogIndex) - 1;
    UINT32 ringSlot = (UINT32)(logIdx & 63);
    g_Hv.ExitLog[ringSlot].ExitReason = reason;
    g_Hv.ExitLog[ringSlot].CpuIndex = vcpu ? vcpu->ProcessorIndex : 0xFFFFFFFFu;
    g_Hv.ExitLog[ringSlot].GuestRip = rip;
    g_Hv.ExitLog[ringSlot].GuestRsp = rsp;
    g_Hv.ExitLog[ringSlot].ExitQualification = qual;
    g_Hv.ExitLog[ringSlot].Timestamp = __rdtsc();
  }

  if (g_Mailbox != NULL && HvMailboxValid(g_Mailbox)) {
    UINT32 idx = g_Mailbox->TotalExitCount & 15u;
    g_Mailbox->LastExitReason[idx]  = reason;
    g_Mailbox->LastExitCpu[idx]     = vcpu ? vcpu->ProcessorIndex : 0xFFFFFFFFu;
    g_Mailbox->LastExitRipLow[idx]  = (UINT32)rip;
    g_Mailbox->LastExitRipHigh[idx] = (UINT32)(rip >> 32);
    g_Mailbox->TotalExitCount++;
  }

  BOOLEAN resume = TRUE;

  switch (reason) {
  case EXIT_REASON_CPUID:
    resume = HandleCpuid(vcpu, regs);
    break;

  case EXIT_REASON_VMCALL:
    resume = HandleVmcall(vcpu, regs);
    break;

  case EXIT_REASON_EXCEPTION_NMI:
    HandleNmi();
    break;

  case EXIT_REASON_EXT_INTERRUPT:
    HandleExternalInterrupt();
    break;

  case EXIT_REASON_XSETBV:
    HandleXsetbv(vcpu, regs);
    break;

  case EXIT_REASON_CR_ACCESS:
    // Reachable: the CR4 guest/host mask owns VMXE, so a guest write that
    // changes CR4 bit 13 exits here. Handled above; never fall through to
    // the default spin.
    HandleCrAccess(vcpu, regs);
    break;

  case EXIT_REASON_EPT_VIOLATION:
    resume = HandleEptViolation(vcpu);
    break;

  case EXIT_REASON_EPT_MISCONFIG:
    resume = HvDevirtualizeThisCpu(vcpu, HV_DEVIRT_EPT_MISCONFIG);
    break;

  case EXIT_REASON_TRIPLE_FAULT:
    resume = HvDevirtualizeThisCpu(vcpu, HV_DEVIRT_TRIPLE_FAULT);
    break;

  case EXIT_REASON_VMCLEAR:
  case EXIT_REASON_VMLAUNCH:
  case EXIT_REASON_VMPTRLD:
  case EXIT_REASON_VMPTRST:
  case EXIT_REASON_VMREAD:
  case EXIT_REASON_VMRESUME:
  case EXIT_REASON_VMWRITE:
  case EXIT_REASON_VMXOFF:
  case EXIT_REASON_VMXON:
  case EXIT_REASON_INVEPT:
  case EXIT_REASON_INVVPID:
  case EXIT_REASON_GETSEC: {
    // VMX instructions (and GETSEC, which needs SMX) a guest cannot legally
    // execute. VT-x is reported present-but-firmware-disabled, so VMXON would
    // fail and none of these are usable; bare metal #UDs on all of them, and
    // so does this. Without this case they fell into default and spun.
    UINT64 info = 6 | (3ULL << 8) | (1ULL << 31);
    __vmx_vmwrite(VMCS_ENTRY_INTERRUPTION_INFO, info);
    UINT64 len = 0;
    __vmx_vmread(VMCS_EXIT_INSTR_LENGTH, &len);
    __vmx_vmwrite(VMCS_ENTRY_INSTR_LENGTH, len);
  } break;

  case EXIT_REASON_RDMSR:
    HandleRdmsr(vcpu, regs);
    break;

  case EXIT_REASON_WRMSR:
    HandleWrmsr(vcpu, regs);
    break;

  case EXIT_REASON_INVD:
    __wbinvd();
    AdvanceGuestRip();
    break;

  case EXIT_REASON_HLT:
    // HLT is an instruction — advance RIP past it and set guest activity state
    // to HLT so VM-entry parks the processor until a wake event.
    // Activity states: 0=active, 1=HLT, 2=shutdown, 3=wait-for-SIPI.
    __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 1);
    AdvanceGuestRip();
    break;

  case EXIT_REASON_INVLPG:
    {
      UINT64 gla = 0;
      __vmx_vmread(VMCS_EXIT_QUALIFICATION, &gla);
      UINT64 desc[2];
      desc[0] = (UINT64)(vcpu->ProcessorIndex + 1);
      desc[1] = gla;
      if (HvAsmInvvpid(INVVPID_INDIVIDUAL_ADDRESS, desc) != 0)
        HvEptInvalidate();
    }
    AdvanceGuestRip();
    break;

  case EXIT_REASON_APIC_ACCESS:
    // Instruction-caused exit (not async) — must advance RIP to avoid spin.
    AdvanceGuestRip();
    break;

  case EXIT_REASON_PAUSE:
    // PAUSE-loop exiting is off; stepping over a PAUSE is harmless.
    AdvanceGuestRip();
    break;

  case EXIT_REASON_WBINVD:
    // WBINVD exiting is off; flushing the caches in root is exact.
    __wbinvd();
    AdvanceGuestRip();
    break;

  // ── Defensive handlers ────────────────────────────────────────────────────
  // These exit reasons are NOT requested by the VMCS controls but some CPUs
  // force the corresponding control bit via FIXED0. Reaching `default` would
  // devirtualize the CPU, which crashes post-ExitBootServices. Advancing RIP
  // is always safe: it makes the guest skip the instruction. The functional
  // loss (a dropped DR write, an unemulated IN) is acceptable as a survival
  // strategy for a control bit we never asked for.
  //
  // The first group (PENDING_INTERRUPT and friends) are async / state-signalling
  // exits with no instruction to skip - they just `break` and let VM-entry
  // deliver whatever's pending. The second group (TASK_SWITCH .. RDTSCP) are
  // instruction-caused exits that need RIP advanced.
  case EXIT_REASON_PENDING_INTERRUPT:
  case EXIT_REASON_APIC_WRITE:
  case EXIT_REASON_VIRTUALIZED_EOI:
  case EXIT_REASON_TPR_BELOW:
  case EXIT_REASON_PML_FULL:
  case EXIT_REASON_SPP_EVENT:
  case EXIT_REASON_BUS_LOCK:
  case EXIT_REASON_NOTIFICATION:
  case EXIT_REASON_INSTRUCTION_TIMEOUT:
    break;

  // Instruction-caused exits whose VMCS controls we never set but which some
  // CPUs may still force via FIXED0 (or that fire from obscure guest state
  // this driver has not been seen to encounter). Each is an instruction the
  // guest just tried to execute, so we advance guest RIP past it; the semantic
  // loss (an uncaptured RDTSC read, a dropped MOV DR, an unemulated IN/OUT) is
  // a far better outcome than devirtualizing a running system. Pass 99
  // reinstates these cases - Pass 97 was documented as adding them but the
  // code shipped without any of them in the dispatcher.
  case EXIT_REASON_TASK_SWITCH:
  case EXIT_REASON_DR_ACCESS:
  case EXIT_REASON_IO:
  case EXIT_REASON_RDPMC:
  case EXIT_REASON_RDTSC:
  case EXIT_REASON_RSM:
  case EXIT_REASON_MWAIT:
  case EXIT_REASON_MONITOR:
  case EXIT_REASON_GDTR_IDTR:
  case EXIT_REASON_LDTR_TR:
  case EXIT_REASON_RDTSCP:
    AdvanceGuestRip();
    break;

  case EXIT_REASON_INIT:
    __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 3);
    break;

  case EXIT_REASON_SIPI: {
    UINT64 qual = 0;
    __vmx_vmread(VMCS_EXIT_QUALIFICATION, &qual);
    UINT64 vector = qual & 0xFF;

    // Reset VMCS guest state to real mode for AP startup.
    // Unrestricted guest (PROC2_UNRESTRICTED_GUEST) allows PE=0, PG=0.

    // Code segment: real-mode at the SIPI vector address
    __vmx_vmwrite(VMCS_GUEST_CS_SEL,    vector << 8);
    __vmx_vmwrite(VMCS_GUEST_CS_BASE,   vector << 12);
    __vmx_vmwrite(VMCS_GUEST_CS_LIMIT,  0xFFFF);
    __vmx_vmwrite(VMCS_GUEST_CS_ACCESS, 0x9B); // present, code, RW, accessed

    // Data segments: real-mode defaults (selector 0, base 0)
    __vmx_vmwrite(VMCS_GUEST_SS_SEL,    0);
    __vmx_vmwrite(VMCS_GUEST_SS_BASE,   0);
    __vmx_vmwrite(VMCS_GUEST_SS_LIMIT,  0xFFFF);
    __vmx_vmwrite(VMCS_GUEST_SS_ACCESS, 0x93); // present, data, RW, accessed

    __vmx_vmwrite(VMCS_GUEST_DS_SEL,    0);
    __vmx_vmwrite(VMCS_GUEST_DS_BASE,   0);
    __vmx_vmwrite(VMCS_GUEST_DS_LIMIT,  0xFFFF);
    __vmx_vmwrite(VMCS_GUEST_DS_ACCESS, 0x93);

    __vmx_vmwrite(VMCS_GUEST_ES_SEL,    0);
    __vmx_vmwrite(VMCS_GUEST_ES_BASE,   0);
    __vmx_vmwrite(VMCS_GUEST_ES_LIMIT,  0xFFFF);
    __vmx_vmwrite(VMCS_GUEST_ES_ACCESS, 0x93);

    __vmx_vmwrite(VMCS_GUEST_FS_SEL,    0);
    __vmx_vmwrite(VMCS_GUEST_FS_BASE,   0);
    __vmx_vmwrite(VMCS_GUEST_FS_LIMIT,  0xFFFF);
    __vmx_vmwrite(VMCS_GUEST_FS_ACCESS, 0x93);

    __vmx_vmwrite(VMCS_GUEST_GS_SEL,    0);
    __vmx_vmwrite(VMCS_GUEST_GS_BASE,   0);
    __vmx_vmwrite(VMCS_GUEST_GS_LIMIT,  0xFFFF);
    __vmx_vmwrite(VMCS_GUEST_GS_ACCESS, 0x93);

    // LDTR: unusable
    __vmx_vmwrite(VMCS_GUEST_LDTR_SEL,    0);
    __vmx_vmwrite(VMCS_GUEST_LDTR_BASE,   0);
    __vmx_vmwrite(VMCS_GUEST_LDTR_LIMIT,  0xFFFF);
    __vmx_vmwrite(VMCS_GUEST_LDTR_ACCESS, 0x10000); // unusable

    // TR: 16-bit busy TSS (type 3) or 32-bit busy TSS (type 11 / 0x8B).
    // Intel SDM Vol 3C §26.3.1.2: The selector field for TR must NOT be 0000H.
    // Use the valid host TSS slot pre-allocated for this CPU at bring-up.
    // Keep the TSS base from the original VMCS setup (points at &vcpu->Tss).
    UINT16 tssSel = 0;
    if (g_HvHostBaseTssSlot != 0 && vcpu != NULL) {
      tssSel = g_HvHostBaseTssSlot + (UINT16)(vcpu->ProcessorIndex * 16u);
    } else {
      tssSel = 0x40; // Architectural non-zero TSS selector fallback
    }
    __vmx_vmwrite(VMCS_GUEST_TR_SEL,      (UINT64)tssSel);
    __vmx_vmwrite(VMCS_GUEST_TR_LIMIT,    (UINT64)(sizeof(HV_TSS64) - 1));
    __vmx_vmwrite(VMCS_GUEST_TR_ACCESS,   0x8B); // present, busy 32-bit TSS

    // GDTR/IDTR: real-mode defaults (base 0, limit 0xFFFF). The AP
    // trampoline code will LGDT before enabling protected mode.
    __vmx_vmwrite(VMCS_GUEST_GDTR_BASE,   0);
    __vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT,  0xFFFF);
    __vmx_vmwrite(VMCS_GUEST_IDTR_BASE,   0);
    __vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT,  0x3FF); // real-mode IVT: 256×4 = 1024

    // CR0: real mode. With unrestricted guest, PE and PG can be 0 even
    // though VMX_CR0_FIXED0 reports them as required.
    UINT64 sipiCr0 = (__readmsr(MSR_IA32_VMX_CR0_FIXED0) & ~(CR0_PE | CR0_PG))
                   & __readmsr(MSR_IA32_VMX_CR0_FIXED1);
    __vmx_vmwrite(VMCS_GUEST_CR0, sipiCr0);
    __vmx_vmwrite(VMCS_CR0_READ_SHADOW, sipiCr0);

    __vmx_vmwrite(VMCS_GUEST_CR3, 0);

    // CR4: minimum required by FIXED0
    __vmx_vmwrite(VMCS_GUEST_CR4, __readmsr(MSR_IA32_VMX_CR4_FIXED0));
    __vmx_vmwrite(VMCS_CR4_READ_SHADOW, 0);

    // EFER: clear LMA and LME (real mode, not long mode)
    __vmx_vmwrite(VMCS_GUEST_EFER, 0);

    // Entry controls: clear IA32E_MODE_GUEST (guest is 16-bit real mode)
    UINT64 sipiEntryCtls = 0;
    __vmx_vmread(VMCS_ENTRY_CONTROLS, &sipiEntryCtls);
    sipiEntryCtls &= ~(UINT64)ENTRY_CTRL_IA32E_MODE_GUEST;
    __vmx_vmwrite(VMCS_ENTRY_CONTROLS, sipiEntryCtls);

    // RIP, RSP, RFLAGS, DR7
    __vmx_vmwrite(VMCS_GUEST_RIP, 0);
    __vmx_vmwrite(VMCS_GUEST_RSP, 0);
    __vmx_vmwrite(VMCS_GUEST_RFLAGS, 2);
    __vmx_vmwrite(VMCS_GUEST_DR7, 0x400);

    __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY, 0);
    __vmx_vmwrite(VMCS_GUEST_PENDING_DBG_EXCEPT, 0);
    __vmx_vmwrite(VMCS_GUEST_DEBUGCTL, 0);
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_CS, 0);
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, 0);
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, 0);
    // PAT: power-on default (SDM Table 11-11). ENTRY_CTRL_LOAD_PAT is set,
    // so the hardware loads this on every VM entry.
    __vmx_vmwrite(VMCS_GUEST_PAT, 0x0007040600070406ULL);

    __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0); // active
  } break;

  case EXIT_REASON_PREEMPT_TIMER:
  case EXIT_REASON_NMI_WINDOW:
  case EXIT_REASON_IO_SMI:
  case EXIT_REASON_SMI:
    break;

  case EXIT_REASON_MTF:
    if (vcpu && vcpu->MtfRestorePending) {
      // The pending single-step names a slot AND the install epoch it was armed
      // for. Both halves are checked, because Active alone stopped being enough
      // the moment slots became reusable: a slot released by an unhook and
      // taken by the next hook is Active again, and restoring the PREVIOUS
      // occupant's shadow page would rewrite this page's EPT entry to the wrong
      // physical page. A mismatch is a rejection, not a restore - MTF is still
      // switched off below, so a refused restore cannot single-step for ever.
      UINT32 mtfSlot = HvHookTagSlot(vcpu->MtfHookTag);
      if (mtfSlot < HV_MAX_EPT_HOOKS) {
        HV_EPT_HOOK *mtfHook = &g_Hv.EptHooks[mtfSlot];
        if (mtfHook->Active && mtfHook->PtePtr != NULL &&
            HvHookTagMatches(vcpu->MtfHookTag, mtfSlot, mtfHook->Epoch)) {
          // Live mutation. The publish is the HvEptInvalidate() below - after
          // the restore, never before it; see the INVARIANT note in
          // ../hv_ept_gen.h.
          mtfHook->PtePtr->PhysAddr = mtfHook->ShadowPagePa >> 12;
          mtfHook->PtePtr->Read    = 0;
          mtfHook->PtePtr->Write   = 0;
          mtfHook->PtePtr->Execute = 1;
          HvEptInvalidate();
        }
      }
      vcpu->MtfRestorePending = FALSE;
      SIZE_T procCtl = 0;
      __vmx_vmread(VMCS_PROC_BASED_CONTROLS, &procCtl);
      procCtl &= ~(SIZE_T)PROC_BASED_MONITOR_TRAP;
      __vmx_vmwrite(VMCS_PROC_BASED_CONTROLS, procCtl);
    }
    break;

  case EXIT_REASON_INVALID_GUEST:
    resume = HvDevirtualizeThisCpu(vcpu, HV_DEVIRT_INVALID_GUEST);
    break;

  case EXIT_REASON_MCE_DURING_ENTRY:
    resume = HvDevirtualizeThisCpu(vcpu, HV_DEVIRT_MCE_DURING_ENTRY);
    break;

  case EXIT_REASON_MSR_LOADING:
    resume = HvDevirtualizeThisCpu(vcpu, HV_DEVIRT_MSR_LOADING);
    break;

  default:
    // A definite outcome, never a spin. Every exit the VMCS controls can
    // produce is classified above; reaching here means the CPU reported one
    // this build does not model. Resuming without advancing RIP would
    // re-execute the same instruction for ever - a hang, the worst possible
    // failure - and advancing it would guess at an instruction length the
    // VMCS need not even hold for that exit. Devirtualising this CPU is the
    // safe resolution: the assembly stub reads the guest's RIP and RSP back
    // out of the VMCS and resumes it natively, so the guest continues
    // exactly where it was. (Mirrors HvDrv/hv_exit.c.)
    resume = HvDevirtualizeThisCpu(vcpu, HV_DEVIRT_UNKNOWN_REASON);
    break;
  }

  // If a vectored event was being delivered when this exit occurred, re-inject
  // it on the way back so it is not silently dropped (SDM Vol 3 §27.2.4).
  // Only re-inject if no handler above already wrote an event — two injections
  // cause VM-entry failure.
  if (resume) {
    UINT64 alreadyInjected = 0;
    __vmx_vmread(VMCS_ENTRY_INTERRUPTION_INFO, &alreadyInjected);
    if (!(alreadyInjected & (1ULL << 31))) {
      UINT64 idtInfo = 0;
      __vmx_vmread(VMCS_IDT_VECTORING_INFO, &idtInfo);
      if (idtInfo & (1ULL << 31)) {
        __vmx_vmwrite(VMCS_ENTRY_INTERRUPTION_INFO, idtInfo);
        if (idtInfo & (1ULL << 11)) {
          UINT64 errCode = 0;
          __vmx_vmread(VMCS_IDT_VECTORING_ERROR, &errCode);
          __vmx_vmwrite(VMCS_ENTRY_EXCEPTION_ERROR, errCode);
        }
      }
    }
  }

  return resume;
}
