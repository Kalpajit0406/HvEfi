// hv_efi_stage.h - boot-stage codes shared by the HvEfi DXE driver (which
// writes them) and tools/diag/hv_efi_diag.c (which decodes them).
//
// Why this exists: a real machine gives the DXE driver no console. When the
// driver failed, the only externally visible trace was that the auth ticket had
// been consumed - indistinguishable from "the driver never loaded at all", and
// with no hint as to which step failed. Each stage is now persisted in a small
// EFI variable so the OS can read back exactly how far bring-up got.
//
// Deliberately dependency-free (no Uefi.h, no EDK2 types): the EDK2 build and a
// plain Win32 diagnostic tool both include this file.
//
// Keep this file ASCII-only.

#ifndef HV_EFI_STAGE_H
#define HV_EFI_STAGE_H

// 4-byte tag in the status blob so a stale/unrelated variable is not
// misreported as a stage. 'HEV1'.
#define HV_STAGE_MAGIC          0x48455631u

// Stages reached. These match the numbered steps in HvEfiDriverEntry.
#define HV_STAGE_ENTRY          0u
#define HV_STAGE_CPU_OK         1u    // Step 1  VMX support + CR4/feature checks
#define HV_STAGE_MP_OK          2u    // Step 2  EFI_MP_SERVICES_PROTOCOL located
#define HV_STAGE_HOSTPT_OK      3u    // Step 3  host identity page tables built
#define HV_STAGE_NONCE_OK       4u    // Step 4  RDRAND session nonce
#define HV_STAGE_TICKET_OK      5u    // Step 5  auth ticket read from NVRAM
#define HV_STAGE_KEYS_OK        6u    // Step 6  session keys derived
#define HV_STAGE_DECOY_OK       7u    // Step 7  decoy pages allocated
#define HV_STAGE_VMXINIT_OK     8u    // Step 8  per-CPU VMX state + EPT ready
#define HV_STAGE_HIDDEN_OK      9u    // Step 9  hidden-page list collected
#define HV_STAGE_EPTHIDE_OK     10u   // Step 10 EPT hiding applied
#define HV_STAGE_CR3OFF_OK      11u   // Step 11 CR3 offset set
#define HV_STAGE_VIRT_OK        12u   // Step 12 all CPUs virtualized
#define HV_STAGE_DONE           13u   // Step 13 secrets wiped, returning success
#define HV_STAGE_DARK           14u   // driver intentionally stood down

// Failures carry bit 15. HV_STAGE_FAIL(n) = "failed while at/after step n".
#define HV_STAGE_FAILED         0x8000u
#define HV_STAGE_FAIL(step)     (HV_STAGE_FAILED | (unsigned)(step))


// ── Step-12 (all-CPU launch) failure detail codec ───────────────────────────────
//
// The boot mailbox has ONE Detail word, and every AP writes to it. Pass 94
// replaced the old "last writer wins" with a per-VCPU record (VCPU.LaunchError)
// plus a single deterministic summary, so the word that reaches the receipt has
// to carry three facts in a fixed layout or the diagnosis is a bare number.
//
//   bits  7:0   VM-instruction error (MSR 0x4400), valid when class is
//               HV_STAGE12_CLASS_VMENTRY
//   bits 15:8   HV_STAGE12_CLASS_*
//   bits 23:16  the processor handle whose bring-up failed (0 = unknown)
//
// Deliberately dependency-free and pure so tools/diag/hv_efi_diag.c can decode a
// receipt without pulling in EDK2 types - same reason this header exists.

#define HV_STAGE12_CLASS_VMENTRY   1u  // VMLAUNCH failed; MSR 0x4400 valid
#define HV_STAGE12_CLASS_VMXON     2u
#define HV_STAGE12_CLASS_VMCLEAR   3u
#define HV_STAGE12_CLASS_VMPTRLD   4u
#define HV_STAGE12_CLASS_VMCS      5u  // HvVmcsSetupCpu refused
#define HV_STAGE12_CLASS_NO_HANDLE 6u  // processor handle unresolvable (Pass 94)
#define HV_STAGE12_CLASS_TIMEOUT   7u  // StartupAllAPs timed out on this AP
#define HV_STAGE12_CLASS_NONE      0u

static __inline unsigned int HvStage12DetailEncode(unsigned int cls,
                                                   unsigned int vmErr,
                                                   unsigned int handle)
{
    return ((cls & 0xFFu) << 8) | ((handle & 0xFFu) << 16) | (vmErr & 0xFFu);
}

static __inline unsigned int HvStage12DetailClass(unsigned int d)
{ return (d >> 8) & 0xFFu; }

static __inline unsigned int HvStage12DetailVmErr(unsigned int d)
{ return d & 0xFFu; }

static __inline unsigned int HvStage12DetailHandle(unsigned int d)
{ return (d >> 16) & 0xFFu; }


#endif // HV_EFI_STAGE_H
