// hv_hostidt.h - host-owned IDT and GDT construction for VMX root.
//
// WHY
//   The VMCS host IDTR/GDTR base fields are reloaded by the processor on EVERY
//   VM-exit. Before this header they were set to whatever the firmware's own
//   tables were at VMLAUNCH time. That works until the OS takes over: EDK2
//   reclaims the firmware GDT/IDT around ExitBootServices, and from then on
//   every VM-exit loads a GDTR/IDTR pointing at recycled memory. A bad IDTR in
//   root mode turns an NMI into a #GP, and a #GP whose handler is the recycled
//   table is a triple fault - a hard reset of the guest with the hypervisor
//   still installed. There is no debugger and no receipt to explain it.
//
//   This is not hypothetical. Both external reviews of this project flagged it;
//   tandasat/MiniVisorPkg (the closest UEFI-DXE analog: DXE driver, MP-services
//   bring-up, EPT, OS handoff) calls the same failure out by name in
//   Sources/Platform/EFI/EfiHostInitialization.c:
//
//     "Its own interrupt descriptor table is required for the same reason.
//      After transitioning to the virtual mode, the existing IDT becomes
//      invalid. One might think the host IDT is not relevant as interrupts are
//      disabled. The fact is that NMI still occurs while the host is running."
//
//   The HVDRV exit stub's own comment says "HOST_IDTR_BASE is the guest's IDTR,
//   so an interrupt or NMI landing mid-handler would vector to a guest ISR in VMX
//   root with the host CR3 loaded - fatal". That reasoning is right about the
//   hazard and wrong about the remedy: the `cli` in the stub clears IF, which
//   masks only maskable interrupts. NMI and machine-check are not maskable by
//   IF, they are delivered with the host IDTR, and they ignore IF entirely. The
//   guest IDTR is therefore not a safe fallback - it is the thing that is about
//   to be freed.
//
// ARCHITECTURE NOTE (Intel SDM Vol 3D, Appendix B)
//   There is NO VMCS_HOST_GDTR_LIMIT and NO VMCS_HOST_IDTR_LIMIT field. The
//   host-state VMCS block defines host GDTR/IDTR BASE only (0x6C0C / 0x6C0E);
//   the complete VMCS_HOST_* set is 27 fields and neither limit is among them.
//   Do not "fix" this by adding limit fields - writing encoding 0x0C10/0x0C12
//   would either be a no-op or hit an unrelated field. The limit side of the
//   problem is solved by owning the tables and making them fully populated,
//   not by writing more VMCS.
//
//   (The *guest* limits are real fields - VMCS_GUEST_GDTR_LIMIT 0x4810 and
//   VMCS_GUEST_IDTR_LIMIT 0x4812 - and hv_vmcs.c already writes both.)
//
// CONTRACT
//   - The IDT is HV_IDT_ENTRIES interrupt gates, each HV_IDT_GATE_BYTES.
//     Gate type byte 0x8E: present, DPL 0, 64-bit interrupt gate. An interrupt
//     gate (not a trap gate) clears IF on entry, which is what we want in root
//     mode - it stops a second interrupt from re-entering the stub.
//   - Every gate points at the same C handler. CPL in VMX root is 0, and a
//     hardware exception delivered at CPL 0 pushes NO stack frame, so the
//     vector number is not recoverable from C without a per-vector asm stub.
//     The handler therefore records "a root-mode exception happened" and stops
//     the world; the vector is not captured. That is a deliberate trade:
//     a diagnosed freeze beats an unexplained triple fault.
//   - The GDT copy is byte-for-byte, limit preserved, so every guest segment
//     selector still resolves to the same descriptor in root mode. Copying
//     matters as much as the IDT: the host GDTR is reloaded on every exit too,
//     and a recycled GDT breaks any far jump or segment load in the stub.
//
//   Both tables must live in memory that outlives ExitBootServices. The
//   callers place them in the hypervisor image's own .data, which stays
//   resident for as long as the exit handler's code does.
//
// Deliberately dependency-free (no Uefi.h, no wdm.h, no string.h): the EDK2
// build, the WDK build and a plain Win32 unit test all include this file.
// Keep this file ASCII-only and free of any OS calls - it is pure logic over
// values.

#ifndef HV_HOSTIDT_H
#define HV_HOSTIDT_H

// ── Host IDT ─────────────────────────────────────────────────────────────────

#define HV_IDT_ENTRIES            256u
#define HV_IDT_GATE_BYTES         16u

// P=1, S=0, DPL=00b, type=1110b (64-bit interrupt gate).
#define HV_IDT_GATE_INTERRUPT     0x8Eu

// A plausible architectural GDT. The firmware's is far smaller; this is a
// ceiling, and HvCopyHostGdt refuses anything that would not fit rather than
// truncating (a truncated GDT silently changes what a selector resolves to).
#define HV_HOST_GDT_MAX_BYTES     0x1000u

// Build one 16-byte x64 interrupt gate. Written byte-wise rather than as a
// struct so the layout is explicit and cannot drift with compiler padding or
// endianness. Layout (SDM Vol 3A, Table 6-8 Interrupt Gate Descriptor):
//   [0:1]  offset 15:0     [2:3]  selector    [4] IST    [5] type-attributes
//   [6:7]  offset 31:16    [8:11] offset 63:32    [12:15] reserved (0)
static __inline
void HvIdtFillGate(UINT8 *gate, UINT64 handler, UINT16 selector)
{
    gate[0]  = (UINT8)(handler);
    gate[1]  = (UINT8)(handler >> 8);
    gate[2]  = (UINT8)(selector);
    gate[3]  = (UINT8)(selector >> 8);
    gate[4]  = 0;                       // IST 0 - use the current RSP
    gate[5]  = HV_IDT_GATE_INTERRUPT;
    gate[6]  = (UINT8)(handler >> 16);
    gate[7]  = (UINT8)(handler >> 24);
    gate[8]  = (UINT8)(handler >> 32);
    gate[9]  = (UINT8)(handler >> 40);
    gate[10] = (UINT8)(handler >> 48);
    gate[11] = (UINT8)(handler >> 56);
    gate[12] = 0;                       // reserved, must be zero
    gate[13] = 0;
    gate[14] = 0;
    gate[15] = 0;
}

// Reconstruct the handler address from a gate. Used by the unit test to prove
// the write/read round trip, and to assert no gate was left zeroed.
static __inline
UINT64 HvIdtReadGateOffset(const UINT8 *gate)
{
    return  (UINT64)gate[0]
         | ((UINT64)gate[1]  << 8)
         | ((UINT64)gate[6]  << 16)
         | ((UINT64)gate[7]  << 24)
         | ((UINT64)gate[8]  << 32)
         | ((UINT64)gate[9]  << 40)
         | ((UINT64)gate[10] << 48)
         | ((UINT64)gate[11] << 56);
}

// Fill a whole host IDT. Returns the number of entries written, or 0 if the
// arguments cannot produce a valid table. A zero handler or a zero selector is
// rejected rather than installed: a gate pointing at address 0 turns the next
// NMI into a jump to null, which is the exact failure this header exists to
// remove.
static __inline
UINT32 HvBuildHostIdt(UINT8 *idt, UINT32 idtBytes,
                      UINT64 handler, UINT16 selector)
{
    UINT32 i;
    UINT32 needed;

    if (idt == 0) return 0;
    if (handler == 0) return 0;
    if (selector == 0) return 0;        // null selector cannot be a gate target
    if ((selector & 3) != 0) return 0;  // RPL/TI bits are not part of a flat CS

    needed = HV_IDT_ENTRIES * HV_IDT_GATE_BYTES;
    if (idtBytes < needed) return 0;    // refuse; never partially build

    for (i = 0; i < HV_IDT_ENTRIES; i++) {
        HvIdtFillGate(idt + (i * HV_IDT_GATE_BYTES), handler, selector);
    }
    return HV_IDT_ENTRIES;
}

// ── Host GDT ─────────────────────────────────────────────────────────────────

// Copy the live firmware GDT into memory the hypervisor owns, preserving the
// limit. Returns the number of bytes copied, or 0 if the source limit cannot
// fit in the destination.
//
// The limit is copied verbatim and NOT extended: every selector the VMCS
// already references (CS, SS, DS, ES, FS, GS, TR, LDTR) must resolve to the
// same descriptor in the host copy as it did at VMLAUNCH.
static __inline
UINT32 HvCopyHostGdt(UINT8 *dst, UINT32 dstBytes,
                     UINT64 srcBase, UINT16 srcLimit)
{
    UINT32 i;

    if (dst == 0) return 0;
    if (srcBase == 0) return 0;
    if ((UINT32)srcLimit + 1u > dstBytes) return 0;   // would truncate

    for (i = 0; i <= (UINT32)srcLimit; i++) {
        dst[i] = *(const UINT8 *)(srcBase + i);
    }
    return (UINT32)srcLimit + 1u;
}

// ── 64-bit Task State Segment (TSS) ─────────────────────────────────────────

#ifndef _HV_TSS64_DEFINED
#define _HV_TSS64_DEFINED
#pragma pack(push, 1)
typedef struct _HV_TSS64 {
    UINT32 Reserved0;
    UINT64 Rsp0;
    UINT64 Rsp1;
    UINT64 Rsp2;
    UINT64 Reserved1;
    UINT64 Ist1;
    UINT64 Ist2;
    UINT64 Ist3;
    UINT64 Ist4;
    UINT64 Ist5;
    UINT64 Ist6;
    UINT64 Ist7;
    UINT64 Reserved2;
    UINT16 Reserved3;
    UINT16 IoMapBase;
} HV_TSS64, *PHV_TSS64;
#pragma pack(pop)
#endif

// Write a 16-byte 64-bit TSS descriptor into a GDT buffer at the specified selector.
// Intel SDM Vol 3A Section 3.5 / 7.2.3.
static __inline
void HvSetTssDescriptor(UINT8 *gdt, UINT16 selector, UINT64 tssBase, UINT32 tssLimit)
{
    UINT8 *desc = gdt + (selector & ~7u);
    desc[0]  = (UINT8)(tssLimit & 0xFFu);
    desc[1]  = (UINT8)((tssLimit >> 8) & 0xFFu);
    desc[2]  = (UINT8)(tssBase & 0xFFu);
    desc[3]  = (UINT8)((tssBase >> 8) & 0xFFu);
    desc[4]  = (UINT8)((tssBase >> 16) & 0xFFu);
    desc[5]  = 0x89u; // Present (P=1), DPL=0, S=0, Type=9 (Available 64-bit TSS)
    desc[6]  = (UINT8)((tssLimit >> 16) & 0x0Fu); // Granularity=0 (byte), AVL=0, L=0, D=0
    desc[7]  = (UINT8)((tssBase >> 24) & 0xFFu);
    desc[8]  = (UINT8)((tssBase >> 32) & 0xFFu);
    desc[9]  = (UINT8)((tssBase >> 40) & 0xFFu);
    desc[10] = (UINT8)((tssBase >> 48) & 0xFFu);
    desc[11] = (UINT8)((tssBase >> 56) & 0xFFu);
    desc[12] = 0;
    desc[13] = 0;
    desc[14] = 0;
    desc[15] = 0;
}

#endif // HV_HOSTIDT_H
