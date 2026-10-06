; hv_asm.asm - VMX entry/exit/launch assembly stubs for x64.
;
; Entry points:
;
;   HvAsmVmxEntry  - VMCS_HOST_RIP target. CPU arrives here on every VM-exit.
;                    Saves guest GP + extended (FP/SSE/AVX) state, calls
;                    HvExitHandler, restores on TRUE + VMRESUME, or shuts down
;                    VMX on FALSE.
;
;   HvAsmVmxLaunch - Called from the IPI callback to perform VMLAUNCH with a
;                    deterministic guest RIP (the label right after vmlaunch).
;                    Returns 0 on success (now running as guest), nonzero on failure.
;
;   HvAsmVmxResume - Standalone VMRESUME helper.
;
;   HvAsmWriteCr2  - Write CR2 (no MSVC intrinsic for this).
;
;   HvAsmReadGdtr / HvAsmReadIdtr / HvAsmReadCs..Ldtr - descriptor-table and
;                    segment-selector reads. MSVC's intrin.h (verified on
;                    14.52) declares no __sgdt/__sidt and no __readcs-family
;                    intrinsics, so hvdefs.h maps those portable names onto
;                    these functions.
;
; Extended-state save/restore: the x64 C ABI treats XMM0-5 as volatile, and the
; kernel-mode C exit handler will clobber them. XMM0-5 are the low halves of
; YMM0-5, so a handler that uses any SSE register also destroys the guest's YMM
; upper lanes. Saving only XMM0-15 is therefore not enough for a guest running
; AVX. We XSAVE/XRSTOR every saveable component up to AVX-512, falling back to
; FXSAVE/FXRSTOR on CPUs without OSXSAVE (where AVX cannot exist).
;
;   Stack: HOST_RSP is 64-byte aligned (set in HvVmcsSetupCpu). The 15 GP
;   pushes plus the 8-byte RSP placeholder total 128 bytes, a multiple of 64,
;   so RSP stays 64-byte aligned and the HV_XSAVE_AREA save area below it is
;   aligned as XSAVE requires.
;
;   Note: the XSAVE mask (g_HvStateSaveMask) follows the live XCR0 and includes
;   every enabled component that fits HV_XSAVE_AREA, AMX tile data (~11 KB)
;   included. HvRefreshStateSaveMask recomputes it whenever XCR0 changes, so a
;   guest that enables more state is never resumed with that state unsaved.

; VMCS field encodings (Intel SDM Vol 3, Appendix B)
VMCS_GUEST_RSP  EQU  681Ch
VMCS_GUEST_RIP  EQU  681Eh

; Bytes reserved on the host stack for the HV_UNLOAD_STATE snapshot.
; MUST match HV_UNLOAD_STATE_SIZE in hvdefs.h (static-asserted in C).
HV_UNLOAD_STATE_SIZE EQU 184

; Field offsets into HV_UNLOAD_STATE. MUST match the C struct field order
; (Cr3, Rip, Rsp, CsSel, ...); the devirtualize stub loads the address-space
; switch args from these offsets.
HV_US_CR3    EQU 0
HV_US_RIP    EQU 8
HV_US_RSP    EQU 16
HV_US_CSSEL  EQU 24
HV_US_RFLAGS EQU 152

; Bytes reserved below the host stack top for the extended-state save area.
; MUST match HV_XSAVE_AREA_BYTES in hvdefs.h. Which components are actually
; written is bounded by g_HvStateSaveMask, recomputed there from the live XCR0
; by HvRefreshStateSaveMask.
HV_XSAVE_AREA   EQU  4000h

.code

EXTERN HvExitHandler : PROC
EXTERN HvCaptureUnloadState : PROC
EXTERN HvUnloadRestoreState : PROC

; Extended-state save policy, resolved once at init in HvVmxInitialize so the
; exit path never executes CPUID. A CPUID on every exit and every resume added
; its latency to every hypercall and EPT violation — overhead, and a timing
; signature in its own right.
;
;   g_HvStateSaveMode: 0 = FXSAVE/FXRSTOR, 1 = XSAVE/XRSTOR (OSXSAVE available)
;   g_HvStateSaveMask: EDX:EAX component mask for XSAVE/XRSTOR. It is XCR0
;     restricted to the components that fit the HV_XSAVE_AREA reserved here,
;     and is recomputed whenever XCR0 changes.
EXTERN g_HvStateSaveMode : DWORD
EXTERN g_HvStateSaveMask : DWORD

; Opcode bytes. Encoded with db so they assemble on any ml64 build:
;   FXSAVE  m512  = 0F AE /0  ->  0F AE 04 24   ([rsp] form has a SIB byte)
;   FXRSTOR m512  = 0F AE /1  ->  0F AE 0C 24
;   XSAVE   m512  = 0F AE /4  ->  0F AE 24 24
;   XRSTOR  m512  = 0F AE /5  ->  0F AE 2C 24
;   XGETBV        = 0F 01 D0

; ---------------------------------------------------------------------------
; HvAsmVmxEntry - VM-exit entry point
;
; Stack layout (relative to RSP after the extended-state area is reserved):
;   [RSP + HV_XSAVE_AREA + 00h] = GUEST_REGS.Rax  (GP register save, 128 bytes)
;   [RSP + HV_XSAVE_AREA + 78h] = GUEST_REGS.R15
;   [RSP + 00h]                 = extended state  (XSAVE/FXSAVE area)
; ---------------------------------------------------------------------------

HvAsmVmxEntry PROC FRAME

    ; Save all 16 guest GP registers. Layout matches GUEST_REGS in hvdefs.h.
    push    r15
    .pushreg r15
    push    r14
    .pushreg r14
    push    r13
    .pushreg r13
    push    r12
    .pushreg r12
    push    r11
    .pushreg r11
    push    r10
    .pushreg r10
    push    r9
    .pushreg r9
    push    r8
    .pushreg r8
    push    rdi
    .pushreg rdi
    push    rsi
    .pushreg rsi
    push    rbp
    .pushreg rbp
    sub     rsp, 8          ; placeholder for RSP slot in GUEST_REGS
    .allocstack 8
    push    rbx
    .pushreg rbx
    push    rdx
    .pushreg rdx
    push    rcx
    .pushreg rcx
    push    rax
    .pushreg rax
    ; RSP is now 0 mod 64 (HOST_RSP was 64-aligned, minus 128 bytes of pushes)

    ; Reserve the extended-state save area
    sub     rsp, HV_XSAVE_AREA
    .allocstack HV_XSAVE_AREA
    .endprolog

    ; Save extended state using the policy resolved at init (see the EXTERN
    ; block above): XSAVE with a bounded component mask, or FXSAVE on a CPU
    ; without OSXSAVE.
    cmp     dword ptr [g_HvStateSaveMode], 0
    jz      _save_fxsave

    mov     eax, dword ptr [g_HvStateSaveMask]
    xor     edx, edx
    db      0Fh, 0AEh, 24h, 24h       ; xsave [rsp], mask in EDX:EAX
    jmp     _save_done

_save_fxsave:
    db      0Fh, 0AEh, 04h, 24h       ; fxsave [rsp]

_save_done:
    ; RCX = pointer to GUEST_REGS (above the extended-state area)
    lea     rcx, [rsp + HV_XSAVE_AREA]

    ; Shadow space (32 bytes). RSP is 0 mod 16, sub 20h keeps it 0 mod 16.
    ; CALL pushes 8, making RSP 8 mod 16 inside callee. Correct per x64 ABI.
    sub     rsp, 20h
    call    HvExitHandler
    add     rsp, 20h

    ; AL = return value: TRUE (1) = VMRESUME, FALSE (0) = devirtualize
    test    al, al
    jz      _vmexit_shutdown

    ; -- Resume the guest --------------------------------------------------
    ; Restore extended state from [rsp]. Inlined (not a call) because the
    ; helper would push a return address and move [rsp] off the save area.
    cmp     dword ptr [g_HvStateSaveMode], 0
    jz      _resume_fxsave
    mov     eax, dword ptr [g_HvStateSaveMask]
    xor     edx, edx
    db      0Fh, 0AEh, 2Ch, 24h       ; xrstor [rsp], mask in EDX:EAX
    jmp     _resume_xrestored
_resume_fxsave:
    db      0Fh, 0AEh, 0Ch, 24h       ; fxrstor [rsp]
_resume_xrestored:
    add     rsp, HV_XSAVE_AREA

    ; Restore GP registers
    pop     rax
    pop     rcx
    pop     rdx
    pop     rbx
    add     rsp, 8          ; skip RSP placeholder
    pop     rbp
    pop     rsi
    pop     rdi
    pop     r8
    pop     r9
    pop     r10
    pop     r11
    pop     r12
    pop     r13
    pop     r14
    pop     r15

    vmresume

    ; VMRESUME failed. All GP + extended state are already restored to guest
    ; values. We clobber RAX/RBX/RCX as scratch — unavoidable, and VMRESUME
    ; failure is already a fatal condition.
    jmp     _vmexit_do_vmxoff

_vmexit_shutdown:
    ; -- Devirtualize this CPU (HvExitHandler returned FALSE) ---------------
    cmp     dword ptr [g_HvStateSaveMode], 0
    jz      _shutdown_fxsave
    mov     eax, dword ptr [g_HvStateSaveMask]
    xor     edx, edx
    db      0Fh, 0AEh, 2Ch, 24h       ; xrstor [rsp], mask in EDX:EAX
    jmp     _shutdown_xrestored
_shutdown_fxsave:
    db      0Fh, 0AEh, 0Ch, 24h       ; fxrstor [rsp]
_shutdown_xrestored:
    add     rsp, HV_XSAVE_AREA

    ; Restore GP registers
    pop     rax
    pop     rcx
    pop     rdx
    pop     rbx
    add     rsp, 8          ; skip RSP placeholder
    pop     rbp
    pop     rsi
    pop     rdi
    pop     r8
    pop     r9
    pop     r10
    pop     r11
    pop     r12
    pop     r13
    pop     r14
    pop     r15

_vmexit_do_vmxoff:
    ; Full guest-state devirtualization.
    ;
    ; The old stub restored only GUEST_RSP/RIP and jumped: CR3 still pointed
    ; at the host page tables (freed and zeroed by HvDestroyHostPageTables on
    ; the DXE rollback path -> #PF on the next TLB miss -> hang), and the
    ; descriptor tables/selectors stayed at the VMCS *host* values — post-
    ; ExitBootServices those are firmware tables that no longer exist, so the
    ; first interrupt or segment reload triple-faulted.
    ;
    ; Register discipline: at entry RAX holds the guest RAX — the hypercall
    ; result on the VMCALL path (HvAsmVmcallUnload returns it to C). It is
    ; saved first and restored last. The other volatiles (RCX/RDX/R8-R11) are
    ; dead across any C call by the x64 ABI, so the C helpers may clobber
    ; them; the non-volatiles (RBX/RBP/RSI/RDI/R12-R15) still hold guest
    ; values and are preserved by the C compiler.
    ;
    ; New sequence:
    ;   1. Save guest RAX; snapshot guest state via VMREAD (must precede
    ;      VMXOFF: VMREAD #UDs outside VMX operation) into a struct on the
    ;      host stack. The struct sits above a 32-byte Win64 shadow area so
    ;      the C callees' home-space stores cannot clobber it.
    ;   2. VMXOFF, clear CR4.VMXE (hygiene; the C helper restores the full
    ;      guest CR4 at the end).
    ;   3. C helper restores GDTR/IDTR, selectors, TR/LDTR (via the
    ;      translated physical GDT — the guest VA is not mapped under the
    ;      host CR3 post-EBS), FS/GS bases, PAT, EFER, DR7, CR0, CR4 from the
    ;      snapshot (still on the host stack/CR3) and returns.
    ;   4. Reload the switch args from the snapshot, restore guest RAX, and
    ;      jump to HvAsmSwitchToGuest: guest RSP first (still host CR3),
    ;      then guest CR3, then IRETQ to guest CS:RIP with the guest RFLAGS
    ;      (which the exit handler already advanced past the VMCALL).
    push    rax                     ; guest RAX (hypercall result)
    sub     rsp, 216                ; 184 struct + 32 shadow space.
                                    ; push (8) + sub (216 = 8 mod 16) = 224 =
                                    ; 0 mod 16: the entry RSP alignment is
                                    ; preserved. Both entries to this stub
                                    ; (VMRESUME-failure and shutdown paths)
                                    ; restore RSP to the 64-aligned HOST_RSP,
                                    ; so entry is 0 mod 16 and each CALL below
                                    ; sees RSP 0 mod 16 before the call, i.e.
                                    ; 8 mod 16 inside the callee — correct per
                                    ; the Win64 ABI.
    lea     rcx, [rsp+32]           ; struct above the shadow area
    call    HvCaptureUnloadState

    ; VMXOFF — leave VMX mode
    vmxoff

    ; Clear CR4.VMXE (bit 13)
    mov     rax, cr4
    and     rax, NOT (1 SHL 13)
    mov     cr4, rax

    ; Restore guest descriptor state. Returns on the host stack/CR3.
    lea     rcx, [rsp+32]
    call    HvUnloadRestoreState

    ; Load the address-space switch args from the snapshot, then free it.
    lea     rax, [rsp+32]
    mov     rcx, [rax + HV_US_CR3]
    mov     rdx, [rax + HV_US_RSP]
    movzx   r8d, word ptr [rax + HV_US_CSSEL]
    mov     r9, [rax + HV_US_RIP]
    mov     r10, [rax + HV_US_RFLAGS]
    add     rsp, 216
    pop     rax                     ; guest RAX back (hypercall result)
    jmp     HvAsmSwitchToGuest       ; noreturn

HvAsmVmxEntry ENDP

; ---------------------------------------------------------------------------
; HvAsmSwitchToGuest - Final address-space switch for devirtualization.
;
;   void HvAsmSwitchToGuest(UINT64 cr3, UINT64 rsp, UINT16 csSel, UINT64 rip,
;                           UINT64 rflags);
;   Entered by JMP (not CALL): RCX=cr3, RDX=rsp, R8=csSel, R9=rip, R10=rflags.
;   The C prototype documents the order; the stub passes rflags in R10
;   because a jmp carries no stack arguments.
;
; Loads the guest RSP (still host CR3: safe) then the guest CR3, builds an
; IRETQ frame (RIP/CS/RFLAGS) on the guest stack, and resumes the guest.
; IRETQ — not RETFQ — because the guest RFLAGS (notably IF) must be restored;
; RETFQ would leave the guest running with the exit handler's flags. CPL0->CPL0
; so RSP/SS are not part of the frame. Never returns.
;
; PRECONDITION (DXE): every devirtualization path in this driver runs before
; ExitBootServices, where the guest IS the firmware: the firmware's page
; tables are identity-mapped, so the guest stack VA is valid RAM under the
; host CR3, and this stub (a firmware VA = PA) stays mapped after the CR3
; switch. Do NOT use this sequence post-EBS, where the guest stack is a
; high canonical VA unmapped under the host CR3 and this stub's VA is
; unmapped under the guest CR3 — the post-CR3 push/iretq fetches would #PF.
; ---------------------------------------------------------------------------
HvAsmSwitchToGuest PROC
    ; Order matters: the guest stack is firmware RAM, identity-mapped under
    ; the host CR3 (DXE precondition above), so switching RSP first leaves no
    ; window where an interrupt would use a stack unmapped under the current
    ; CR3. RSP is abandoned here — this never returns.
    mov     rsp, rdx                ; guest stack (still host CR3: safe)
    mov     cr3, rcx                ; guest address space
    push    r10                     ; guest RFLAGS
    push    r8                      ; guest CS selector
    push    r9                      ; guest RIP
    iretq                           ; resume guest with its RFLAGS
HvAsmSwitchToGuest ENDP

; ---------------------------------------------------------------------------
; Small descriptor-table helpers for the C unload path (MSVC has no lgdt).
; ---------------------------------------------------------------------------
HvAsmLoadGdtr PROC
    ; RCX = limit, RDX = base
    sub     rsp, 16
    mov     [rsp], cx
    mov     [rsp+2], rdx
    lgdt    fword ptr [rsp]
    add     rsp, 16
    ret
HvAsmLoadGdtr ENDP

HvAsmLoadIdtr PROC
    ; RCX = limit, RDX = base
    sub     rsp, 16
    mov     [rsp], cx
    mov     [rsp+2], rdx
    lidt    fword ptr [rsp]
    add     rsp, 16
    ret
HvAsmLoadIdtr ENDP

HvAsmLoadSegments PROC
    ; RCX=ds, RDX=es, R8=fs, R9=gs, [rsp+28h]=ss
    mov     ds, cx
    mov     es, dx
    mov     fs, r8w
    mov     gs, r9w
    mov     rax, [rsp+28h]
    mov     ss, ax
    ret
HvAsmLoadSegments ENDP

HvAsmLoadTr PROC
    ; RCX = selector
    ltr     cx
    ret
HvAsmLoadTr ENDP

HvAsmLoadLdtr PROC
    ; RCX = selector
    lldt    cx
    ret
HvAsmLoadLdtr ENDP

HvAsmWriteDr7 PROC
    ; RCX = value (full 64-bit; the __writedr intrinsic truncates to 32 bits)
    mov     dr7, rcx
    ret
HvAsmWriteDr7 ENDP

; ---------------------------------------------------------------------------
; HvAsmVmxLaunch - Performs VMLAUNCH with deterministic guest RIP.
;
; Called from C:  int HvAsmVmxLaunch(void)
; Sets VMCS_GUEST_RSP = current RSP, VMCS_GUEST_RIP = label after vmlaunch.
; Returns 0 on success (now in non-root mode), nonzero on failure.
; ---------------------------------------------------------------------------

HvAsmVmxLaunch PROC FRAME

    ; Save all non-volatile registers (callee-saved in x64 ABI)
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    rbp
    .pushreg rbp
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    pushfq
    .allocstack 8
    .endprolog

    ; Set VMCS_GUEST_RSP = current RSP
    mov     rax, VMCS_GUEST_RSP
    mov     rdx, rsp
    vmwrite rax, rdx

    ; Set VMCS_GUEST_RIP = address of _launch_success label
    mov     rax, VMCS_GUEST_RIP
    lea     rdx, [_launch_success]
    vmwrite rax, rdx

    ; Execute VMLAUNCH
    vmlaunch

    ; If we reach here, VMLAUNCH failed (CF=1 or ZF=1)
    jc      _launch_fail_cf
    jz      _launch_fail_zf

    mov     eax, 3          ; unknown failure
    jmp     _launch_restore

_launch_fail_cf:
    mov     eax, 1          ; CF=1: VMLAUNCH failed, check VMCS error
    jmp     _launch_restore

_launch_fail_zf:
    mov     eax, 2          ; ZF=1: VMLAUNCH failed, check VMCS error
    jmp     _launch_restore

_launch_success:
    ; CPU is now in VMX non-root mode (guest).
    xor     eax, eax        ; return 0 = success

_launch_restore:
    popfq
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rdi
    pop     rsi
    pop     rbx
    ret

HvAsmVmxLaunch ENDP

; ---------------------------------------------------------------------------
; HvAsmVmxResume - standalone VMRESUME
; ---------------------------------------------------------------------------

HvAsmVmxResume PROC
    vmresume
    mov     eax, 1
    ret
HvAsmVmxResume ENDP

; ---------------------------------------------------------------------------
; HvAsmWriteCr2 - Write CR2 (MSVC has no __writecr2 intrinsic)
; RCX = value to write
; ---------------------------------------------------------------------------

HvAsmWriteCr2 PROC
    mov     cr2, rcx
    ret
HvAsmWriteCr2 ENDP

; ---------------------------------------------------------------------------
; HvAsmReadGdtr / HvAsmReadIdtr - Store GDTR / IDTR (SGDT / SIDT).
;
;   void HvAsmReadGdtr(void *dst);   void HvAsmReadIdtr(void *dst);
;
; The store is the raw hardware form: [0] = 16-bit limit, [2] = 64-bit base.
; Callers read it back through the repacking wrappers in hvdefs.h, which keep
; naturally aligned structs correct (a plain struct with a 64-bit Base field
; would have that field at offset 8 and read garbage).
; ---------------------------------------------------------------------------

HvAsmReadGdtr PROC
    sgdt    fword ptr [rcx]
    ret
HvAsmReadGdtr ENDP

HvAsmReadIdtr PROC
    sidt    fword ptr [rcx]
    ret
HvAsmReadIdtr ENDP

; ---------------------------------------------------------------------------
; Segment selector readers. ML64 has no register symbol for LDTR, so that
; selector goes through SLDT; the rest are direct register reads.
; ---------------------------------------------------------------------------

HvAsmReadCs PROC
    mov     ax, cs
    ret
HvAsmReadCs ENDP

HvAsmReadSs PROC
    mov     ax, ss
    ret
HvAsmReadSs ENDP

HvAsmReadDs PROC
    mov     ax, ds
    ret
HvAsmReadDs ENDP

HvAsmReadEs PROC
    mov     ax, es
    ret
HvAsmReadEs ENDP

HvAsmReadFs PROC
    mov     ax, fs
    ret
HvAsmReadFs ENDP

HvAsmReadGs PROC
    mov     ax, gs
    ret
HvAsmReadGs ENDP

HvAsmReadTr PROC
    str     ax
    ret
HvAsmReadTr ENDP

HvAsmReadLdtr PROC
    sldt    ax
    ret
HvAsmReadLdtr ENDP

; ---------------------------------------------------------------------------
; HvAsmVmcallUnload - Authenticated VMCALL for devirtualization.
;
; Called from C:
;   void HvAsmVmcallUnload(UINT64 magic, UINT64 id,
;                           UINT64 p1, UINT64 p2,
;                           UINT64 mac, UINT64 p3);
;
; x64 ABI: RCX=magic, RDX=id, R8=p1, R9=p2, [rsp+28h]=mac, [rsp+30h]=p3
; VMCALL expects: RCX=magic, RDX=id, R8=p1, R9=p2, R10=mac, R11=p3
; ---------------------------------------------------------------------------

HvAsmVmcallUnload PROC
    mov     r10, [rsp+28h]
    mov     r11, [rsp+30h]
    vmcall
    ret
HvAsmVmcallUnload ENDP

; ---------------------------------------------------------------------------
; HvAsmInvept / HvAsmInvvpid - Invalidate EPT / VPID translations.
;
;   int HvAsmInvept(UINT64 type, void *desc16);
;   int HvAsmInvvpid(UINT64 type, void *desc16);
;
; x64 ABI: RCX = type, RDX = pointer to the 128-bit descriptor.
; Returns 0 on success, 1 if the instruction reports failure (CF or ZF set).
;
; Encoded with db rather than the mnemonic so it assembles on any ml64 build:
;   INVEPT   r64, m128 = 66 0F 38 80 /r   (type register = RCX, m128 = [RDX])
;   INVVPID  r64, m128 = 66 0F 38 81 /r
; ---------------------------------------------------------------------------

HvAsmInvept PROC
    db      66h, 0Fh, 38h, 80h, 0Ah     ; invept rcx, [rdx]
    jc      _invept_fail
    jz      _invept_fail
    xor     eax, eax
    ret
_invept_fail:
    mov     eax, 1
    ret
HvAsmInvept ENDP

HvAsmInvvpid PROC
    db      66h, 0Fh, 38h, 81h, 0Ah     ; invvpid rcx, [rdx]
    jc      _invvpid_fail
    jz      _invvpid_fail
    xor     eax, eax
    ret
_invvpid_fail:
    mov     eax, 1
    ret
HvAsmInvvpid ENDP

END
