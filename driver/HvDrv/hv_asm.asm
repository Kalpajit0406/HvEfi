; hv_asm.asm - Assembly stubs for HvDrv Windows kernel driver
.code

; UINT64 HvAsmVmcall(UINT64 magic, UINT64 id, UINT64 p1, UINT64 p2, UINT64 mac, UINT64 p3);
; x64 Calling Convention:
; RCX = magic
; RDX = id
; R8  = p1
; R9  = p2
; [rsp+28h] = mac  -> R10
; [rsp+30h] = p3   -> R11
; Return: RAX = hypercall status / return value
HvAsmVmcall PROC
    mov     r10, [rsp + 28h]
    mov     r11, [rsp + 30h]
    vmcall
    ret
HvAsmVmcall ENDP

END
