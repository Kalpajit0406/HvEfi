// hvdefs.h - Intel VT-x / VMX definitions for the EFI DXE runtime driver.
//
// This header is the EFI-build counterpart of HvDrv/hvdefs.h. It provides the
// same VMX constants, VMCS field encodings, structures and function declarations
// but uses standalone C types + MSVC intrinsics instead of ntddk.h.
//
// Shared source files (hv_exit.c, hv_vmcs.c, hv_asm.asm) include this header
// and compile identically for both the WDK and EFI builds.

#pragma once

#include <intrin.h>
#include "../hv_siphash.h"

// Edk2 has no ntddk.h, so it does not define the WDK's un-prefixed interlocked
// names. intrin.h provides the underscored intrinsic in both trees, so alias
// the WDK spelling here — exactly as the __sgdt/__sidt shims below do. Needed by
// the shared hv_exit.c call site (visible only when the exit telemetry is
// compiled in, i.e. under `#if DBG`).
#ifndef InterlockedIncrement64
#define InterlockedIncrement64 _InterlockedIncrement64
#endif

// ── NT-compatible types (for shared VMX code) ──────────────────────────────
// Only the subset actually used by the VMX, VMCS, exit handler, and EPT code.

#if !defined(_NTDDK_) && !defined(MDE_CPU_X64)
typedef unsigned char       UINT8,  *PUINT8;
typedef unsigned short      UINT16;
typedef unsigned int        UINT32, *PUINT32, ULONG;
typedef unsigned __int64    UINT64, *PUINT64;
typedef __int64             INT64,  LONG64;
typedef long                LONG;
typedef unsigned char       UCHAR, *PUCHAR;
typedef void                VOID,  *PVOID;
typedef char                CHAR;
typedef unsigned __int64    ULONG_PTR, UINT_PTR, SIZE_T, UINTN;
typedef unsigned short      USHORT, WCHAR;

typedef long                NTSTATUS;
#define STATUS_SUCCESS              ((NTSTATUS)0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define STATUS_NOT_SUPPORTED        ((NTSTATUS)0xC00000BBL)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define STATUS_ALREADY_INITIALIZED  ((NTSTATUS)0xC00000BEL)
#define STATUS_DEVICE_CONFIGURATION_ERROR ((NTSTATUS)0xC0000182L)
#define STATUS_INVALID_PARAMETER    ((NTSTATUS)0xC000000DL)
#define STATUS_ALREADY_COMPLETE     ((NTSTATUS)0x00000001L)
#define STATUS_NOT_FOUND            ((NTSTATUS)0xC0000225L)
#define STATUS_ALREADY_REGISTERED   ((NTSTATUS)0xC0000718L)
#define NT_SUCCESS(s)               ((NTSTATUS)(s) >= 0)

typedef unsigned char       BOOLEAN;
#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif

typedef union _LARGE_INTEGER {
    struct { UINT32 LowPart; LONG HighPart; };
    INT64 QuadPart;
} LARGE_INTEGER;

typedef union _PHYSICAL_ADDRESS {
    struct { UINT32 LowPart; LONG HighPart; };
    INT64 QuadPart;
} PHYSICAL_ADDRESS;

// Memory range — matches the WDK's PHYSICAL_MEMORY_RANGE.
// The EFI EPT code populates this from GetMemoryMap.
typedef struct _PHYSICAL_MEMORY_RANGE {
    PHYSICAL_ADDRESS BaseAddress;
    LARGE_INTEGER    NumberOfBytes;
} PHYSICAL_MEMORY_RANGE;

#define PAGE_SIZE           4096
#define MAXULONG64          0xFFFFFFFFFFFFFFFFULL

#define UNREFERENCED_PARAMETER(x) (void)(x)
#ifndef DECLSPEC_ALIGN
#define DECLSPEC_ALIGN(x)   __declspec(align(x))
#endif

// Volatile interlocked ops — MSVC builtins
//
// InterlockedCompareExchange is what hv_hookpool.h's pool and split claims are
// built from. It is the WDK spelling because that is the one name every build
// path can reach: ntddk.h declares it in the WDK tree, the syntax gate's
// ntddk.h stub maps it, and this alias covers EDK2, which has neither.
#define InterlockedIncrement        _InterlockedIncrement
#define InterlockedCompareExchange  _InterlockedCompareExchange
#define InterlockedCompareExchange64 _InterlockedCompareExchange64

// Debug output — no-op in EFI runtime (no console after ExitBootServices).
// The EFI-specific code uses EfiPrint() during the boot phase.
#define KdPrint(x) ((void)0)
#define HV_LOG(x)  ((void)0)

// EFI debug macros — available here so shared files (hv_exit.c, hv_vmcs.c)
// that only include hvdefs.h can use them without pulling in hv_efi.h.
// hv_efi.h also defines these; guards prevent redefinition.
//
// This header is ALSO compiled without any EDK2 headers on the include path:
// tools/syntax-check and tools/unit build the shared VMX sources (hv_exit.c,
// hv_vmcs.c) with neither _NTDDK_ nor MDE_CPU_X64 defined, precisely so the VMX
// core can be type-checked without the firmware. There is no DebugLib there, so
// including it is a hard failure (C1083) for every one of those builds. Define
// the macros as no-ops instead; the EDK2 build gets the real DEBUG() below, in
// the MDE_CPU_X64 branch.
#ifndef EfiPrint
#define EfiPrint(fmt, ...)  ((void)0)
#define EfiFatal(fmt, ...)  ((void)0)
#endif

// Secure zero
#define RtlSecureZeroMemory(dst, sz)  __stosb((unsigned char*)(dst), 0, (sz))
#define RtlZeroMemory(dst, sz)        __stosb((unsigned char*)(dst), 0, (sz))
#define RtlCopyMemory(dst, src, sz)   __movsb((unsigned char*)(dst), (const unsigned char*)(src), (sz))

// Descriptor readers for hv_vmcs.c's non-EFI branch, when this header is used
// without the WDK (tools/syntax-check / tools/unit). The stubs live in
// hv_asm.asm as HvAsmReadGdtr / HvAsmReadIdtr and the WDK header maps the plain
// names onto them, so do the same here rather than inventing a second path.
// GDTR/IDTR are the hardware-format descriptors the stubs repack.
typedef struct { UINT16 Limit; UINT64 Base; } HV_DTR;
extern void HvAsmReadGdtr(void *dst);
extern void HvAsmReadIdtr(void *dst);
#define HvReadGdtr HvAsmReadGdtr
#define HvReadIdtr HvAsmReadIdtr

#if defined(HV_EFI_BUILD)
// hv_vmcs.c's EFI branch calls __sgdt/__sidt, which the real build gets from
// the BaseLib wrappers in the MDE_CPU_X64 branch above. This build has no EDK2
// headers and is syntax-only (-Zs), so plain declarations are enough.
extern void __sgdt(void *dst);
#if _MSC_VER < 1950
/* VS2025+ (_MSC_VER >= 1950) promotes __sidt to a built-in intrinsic. */
extern void __sidt(void *dst);
#endif
#endif

#endif /* _NTDDK_ */

#ifdef MDE_CPU_X64
/* EDK2 provides the base numeric types (ProcessorBind.h) and VOID (Base.h),
 * but not the NT-style pointer typedefs the shared headers use. */
#ifndef _HV_EFI_NT_PTRS_
#define _HV_EFI_NT_PTRS_
typedef VOID *PVOID;
typedef UINT64 *PUINT64;
typedef UINT32 *PUINT32;
typedef UINT8  *PUINT8;
typedef UINT64 SIZE_T;
typedef UINT64 ULONG_PTR;
typedef UINT64 UINT_PTR;
typedef UINT8  UCHAR, *PUCHAR;
typedef UINT16 UINT16, *PUINT16;
typedef UINT32 ULONG, *PULONG;
typedef char   CHAR;
typedef UINT64 *PUINTN;
/* MSVC intrinsics: the map below lives in the skipped _NTDDK_ block, so
 * repeat it here where EDK2 actually compiles. */
#define InterlockedIncrement          _InterlockedIncrement
#define InterlockedCompareExchange    _InterlockedCompareExchange
#define InterlockedCompareExchange64  _InterlockedCompareExchange64

/* GDT/IDT reads: __sgdt/__sidt are WDK-only intrinsics. Under EDK2, map them
 * onto BaseLib's AsmReadGdtr/AsmReadIdtr (IA32_DESCRIPTOR has the same packed
 * {Limit, Base} layout as GDTR/IDTR here). */
#include <Library/BaseLib.h>
typedef struct { UINT16 Limit; UINT64 Base; } HV_DTR;
// NOTE: these are deliberately NOT named __sgdt/__sidt. On MSVC 14.5x __sidt
// is a built-in intrinsic (see the _MSC_VER >= 1950 guard in the HV_EFI_BUILD
// branch above), and defining a function with an intrinsic's name is error
// C2169 ("intrinsic function, cannot be defined") under /Oi — which is what the
// EDK2 module build uses. The readers therefore carry their own names and the
// shared code's spelling is aliased onto them, so no intrinsic name is ever
// defined. Layout is the hardware-format packed descriptor the callers expect.
static __inline void HvEfiReadGdtr(void *dst) {
    IA32_DESCRIPTOR desc;
    AsmReadGdtr(&desc);
    ((HV_DTR *)dst)->Limit = desc.Limit;
    ((HV_DTR *)dst)->Base  = desc.Base;
}
static __inline void HvEfiReadIdtr(void *dst) {
    IA32_DESCRIPTOR desc;
    AsmReadIdtr(&desc);
    ((HV_DTR *)dst)->Limit = desc.Limit;
    ((HV_DTR *)dst)->Base  = desc.Base;
}
#define __sgdt HvEfiReadGdtr
#define __sidt HvEfiReadIdtr

/* Devirtualization helpers implemented in HvEfi/hv_asm.asm. Declared here
 * because calling an undeclared function is warning C4013, which the EDK2
 * module build promotes to an error under /WX. Argument registers follow the
 * x64 ABI (RCX, RDX, R8, R9, then the stack) and match the stubs, which
 * truncate the selector/limit arguments to their 16-bit forms internally. */
void HvAsmLoadGdtr(UINT16 limit, UINT64 base);
void HvAsmLoadIdtr(UINT16 limit, UINT64 base);
void HvAsmLoadSegments(UINT16 ds, UINT16 es, UINT16 fs, UINT16 gs, UINT16 ss);
void HvAsmLoadTr(UINT16 selector);
void HvAsmLoadLdtr(UINT16 selector);
void HvAsmWriteDr7(UINT64 value);   /* 64-bit: __writedr truncates to 32 */

// MSVC-only intrinsic redeclarations: the EDK2 Windows build needs these
// because MDE_CPU_X64 omits <intrin.h>, but a Linux cross-build driven by
// clang-targeting-windows-gnu provides them via mingw's <intrin.h>, and
// redeclaring them with slightly different signatures causes "cannot combine
// specifier" / "function cannot return function type" errors. The cross-build
// defines HV_CROSS_SKIP_INTRIN_REDECLS via its -include shim so this block
// is skipped there and mingw's declarations win.
#ifndef HV_CROSS_SKIP_INTRIN_REDECLS
#pragma intrinsic(__readcr0)
#pragma intrinsic(__readcr3)
#pragma intrinsic(__readcr4)
#pragma intrinsic(__readcr8)
#pragma intrinsic(__readdr)
unsigned __int64 __readcr0(void);
unsigned __int64 __readcr3(void);
unsigned __int64 __readcr4(void);
unsigned __int64 __readcr8(void);
unsigned __int64 __readdr(unsigned int);
#pragma intrinsic(__writecr8)
void __writecr8(unsigned __int64);
#pragma intrinsic(__readmsr)
#pragma intrinsic(__writemsr)
unsigned __int64 __readmsr(unsigned long);
void __writemsr(unsigned long, unsigned __int64);
static __inline UINT16 __readcs(void)  { return (UINT16)AsmReadCs();  }
static __inline UINT16 __readss(void)  { return (UINT16)AsmReadSs();  }
static __inline UINT16 __readds(void)  { return (UINT16)AsmReadDs();  }
static __inline UINT16 __reades(void)  { return (UINT16)AsmReadEs();  }
static __inline UINT16 __readfs(void)  { return (UINT16)AsmReadFs();  }
static __inline UINT16 __readgs(void)  { return (UINT16)AsmReadGs();  }
static __inline UINT16 __readtr(void)  { return (UINT16)AsmReadTr();  }
static __inline UINT16 __readldtr(void){ return (UINT16)AsmReadLdtr(); }
#pragma intrinsic(__rdtsc)
unsigned __int64 __rdtsc(void);
#pragma intrinsic(__readeflags)
unsigned __int64 __readeflags(void);
#pragma intrinsic(__vmx_on)
#pragma intrinsic(__vmx_off)
#pragma intrinsic(__vmx_vmread)
#pragma intrinsic(__vmx_vmwrite)
#pragma intrinsic(__vmx_vmclear)
#pragma intrinsic(__vmx_vmlaunch)
#pragma intrinsic(__vmx_vmresume)
#pragma intrinsic(__vmx_vmptrld)
unsigned char __vmx_on(unsigned __int64 *);
void __vmx_off(void);
unsigned char __vmx_vmread(unsigned int, unsigned __int64 *);
unsigned char __vmx_vmwrite(unsigned int, unsigned __int64);
unsigned char __vmx_vmclear(unsigned __int64 *);
unsigned char __vmx_vmlaunch(void);
unsigned char __vmx_vmresume(void);
unsigned char __vmx_vmptrld(unsigned __int64 *);
#pragma intrinsic(_xgetbv)
#pragma intrinsic(_xsetbv)
unsigned __int64 _xgetbv(unsigned int);
void _xsetbv(unsigned int, unsigned __int64);
#pragma intrinsic(_rdrand64_step)
int _rdrand64_step(unsigned __int64 *);
#pragma intrinsic(_mm_pause)
void _mm_pause(void);
#pragma intrinsic(__cpuid)
#pragma intrinsic(__cpuidex)
void __cpuid(int *, int);
void __cpuidex(int *, int, int);
#pragma intrinsic(__movsb)
#pragma intrinsic(__stosb)
void __movsb(unsigned char *, const unsigned char *, unsigned __int64);
void __stosb(unsigned char *, unsigned char, unsigned __int64);
#endif /* !HV_CROSS_SKIP_INTRIN_REDECLS */
#define RtlCopyMemory(dst, src, sz)   __movsb((unsigned char*)(dst), (const unsigned char*)(src), (sz))
#define RtlZeroMemory(dst, sz)        __stosb((unsigned char*)(dst), 0, (sz))
#define RtlSecureZeroMemory(dst, sz)  __stosb((unsigned char*)(dst), 0, (sz))
typedef __int64 LONG64;

/* NT aggregates the EFI tree's own code uses. Same shapes the skipped block
 * (and the WDK) define; EDK2 has no equivalents. */
typedef union _LARGE_INTEGER {
    struct { UINT32 LowPart; INT32 HighPart; };
    INT64 QuadPart;
} LARGE_INTEGER;
/* PHYSICAL_ADDRESS already exists in MdePkg Base.h as UINT64; the EFI tree's
 * own code never touches it (EfiVaToPA casts), so it is not redefined here. */
typedef struct _PHYSICAL_MEMORY_RANGE {
    LARGE_INTEGER BaseAddress;
    LARGE_INTEGER NumberOfBytes;
} PHYSICAL_MEMORY_RANGE;

#define PAGE_SIZE           0x1000
// DECLSPEC_ALIGN: __declspec(align(x)) is the MSVC spelling. Clang on
// windows-gnu reports it as "unknown attribute 'align' ignored" under
// -Werror. The cross-build shim defines a compatible version first; honour
// it rather than overwriting.
#ifndef DECLSPEC_ALIGN
#define DECLSPEC_ALIGN(x)   __declspec(align(x))
#endif
#define KdPrint(x)          ((void)0)
#define UNREFERENCED_PARAMETER(x) (void)(x)
#define NT_SUCCESS(s)       ((NTSTATUS)(s) >= 0)
#ifndef TRUE
#define TRUE  1
#endif
#ifndef FALSE
#define FALSE 0
#endif
typedef INT32   NTSTATUS;
typedef INT32  LONG;    /* EDK2 has no LONG; NT LONG is 32-bit signed */
#define MAXULONG64                      0xFFFFFFFFFFFFFFFFULL
#define STATUS_SUCCESS                  ((NTSTATUS)0)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_NOT_SUPPORTED            ((NTSTATUS)0xC00000BBL)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_ALREADY_INITIALIZED      ((NTSTATUS)0xC00000BEL)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_ALREADY_COMPLETE         ((NTSTATUS)0x00000001L)
#define STATUS_NOT_FOUND                ((NTSTATUS)0xC0000225L)
#define STATUS_ALREADY_REGISTERED       ((NTSTATUS)0xC0000718L)
#define STATUS_DEVICE_CONFIGURATION_ERROR ((NTSTATUS)0xC0000182L)
#endif
#endif


// Shared page-table walk and page-wise copy (reader/accessor-injected so they
// can be exercised off-target).
#include "../hv_ptwalk.h"
#include "../hv_copy.h"

// ── MSR numbers ──────────────────────────────────────────────────────────────

#define MSR_IA32_FEATURE_CONTROL        0x03A
#define MSR_IA32_VMX_BASIC              0x480
#define MSR_IA32_VMX_PINBASED_CTLS      0x481
#define MSR_IA32_VMX_PROCBASED_CTLS     0x482
#define MSR_IA32_VMX_EXIT_CTLS          0x483
#define MSR_IA32_VMX_ENTRY_CTLS         0x484
#define MSR_IA32_VMX_MISC               0x485
#define MSR_IA32_VMX_CR0_FIXED0         0x486
#define MSR_IA32_VMX_CR0_FIXED1         0x487
#define MSR_IA32_VMX_CR4_FIXED0         0x488
#define MSR_IA32_VMX_CR4_FIXED1         0x489
#define MSR_IA32_VMX_VMCS_ENUM          0x48A
#define MSR_IA32_VMX_PROCBASED_CTLS2    0x48B
#define MSR_IA32_VMX_EPT_VPID_CAP      0x48C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS 0x48D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x48E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS     0x48F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS    0x490

#define MSR_IA32_SYSENTER_CS            0x174
#define MSR_IA32_SYSENTER_ESP           0x175
#define MSR_IA32_SYSENTER_EIP           0x176
#define MSR_IA32_DEBUGCTL               0x1D9
#define MSR_IA32_PERF_GLOBAL_CTRL       0x38F
#define MSR_IA32_PAT                    0x277
#define MSR_IA32_EFER                   0xC0000080
#define MSR_IA32_FS_BASE                0xC0000100
#define MSR_IA32_GS_BASE                0xC0000101
#define MSR_IA32_KERNEL_GS_BASE         0xC0000102
#define MSR_IA32_TSC_AUX                0xC0000103

// ── Feature control bits ────────────────────────────────────────────────────

#define FEATURE_CONTROL_LOCKED          (1ULL << 0)
#define FEATURE_CONTROL_VMXON_OUTSIDE   (1ULL << 2)

// ── Control-register bits ───────────────────────────────────────────────────

#define CR0_PE                          (1ULL << 0)    // protection enable
#define CR0_TS                          (1ULL << 3)    // task switched
#define CR0_PG                          (1ULL << 31)   // paging
#define CR4_VMXE                        (1ULL << 13)
#define CR4_FSGSBASE                    (1ULL << 16)

// ── EFER bits ───────────────────────────────────────────────────────────────

#define EFER_LME                        (1ULL << 8)    // long mode enable
#define EFER_LMA                        (1ULL << 10)   // long mode active

// ── Extended-state save area ────────────────────────────────────────────────
// Bytes the VM-exit stub reserves below the host stack top for XSAVE/XRSTOR,
// and the bound HvRefreshStateSaveMask applies when deciding which XCR0
// components are safe to include. MUST match HV_XSAVE_AREA in hv_asm.asm.
//
// 16 KB covers every component currently defined, AMX tile data (~11 KB)
// included. That headroom is the point: with a smaller area the mask would have
// to exclude the large components, and a guest that enabled one would be
// resumed with its state never having been saved.
#define HV_XSAVE_AREA_BYTES             0x4000

// The save-mask decision (which XCR0 components fit the area) is shared with
// the WDK build and executed off-target by tools/unit/hvxsave_test.c.
#include "../hv_xsave.h"

// Validity of an XSETBV value against a CPUID.0xD:0.EAX supported set. Kept
// here, free of CPUID and intrinsics, so both builds share one definition of
// the rule and it can be exercised off-target. The rules:
//   - every bit set must be supported by the CPU,
//   - XCR0[0] (x87) is mandatory — XSETBV(0,0) is not a legal "disable
//     everything", it #GPs,
//   - XCR0[2] (AVX) requires XCR0[1] (SSE).
static __inline BOOLEAN HvXcr0ValueValid(UINT64 value, UINT64 supported) {
    if ((value & ~supported) != 0) return FALSE;
    if ((value & 1ULL) == 0) return FALSE;
    if ((value & (1ULL << 2)) != 0 && (value & (1ULL << 1)) == 0) return FALSE;
    return TRUE;
}

// ── VMCS field encodings (Intel SDM Vol 3, Appendix B) ──────────────────────

// 16-bit control
#define VMCS_VPID                       0x0000

// 16-bit guest state
#define VMCS_GUEST_ES_SEL               0x0800
#define VMCS_GUEST_CS_SEL               0x0802
#define VMCS_GUEST_SS_SEL               0x0804
#define VMCS_GUEST_DS_SEL               0x0806
#define VMCS_GUEST_FS_SEL               0x0808
#define VMCS_GUEST_GS_SEL               0x080A
#define VMCS_GUEST_LDTR_SEL             0x080C
#define VMCS_GUEST_TR_SEL               0x080E

// 16-bit host state
#define VMCS_HOST_ES_SEL                0x0C00
#define VMCS_HOST_CS_SEL                0x0C02
#define VMCS_HOST_SS_SEL                0x0C04
#define VMCS_HOST_DS_SEL                0x0C06
#define VMCS_HOST_FS_SEL                0x0C08
#define VMCS_HOST_GS_SEL                0x0C0A
#define VMCS_HOST_TR_SEL                0x0C0C

// 64-bit control
#define VMCS_IO_BITMAP_A                0x2000
#define VMCS_IO_BITMAP_B                0x2002
#define VMCS_MSR_BITMAP                 0x2004
#define VMCS_EXIT_MSR_STORE_ADDR        0x2006
#define VMCS_EXIT_MSR_LOAD_ADDR         0x2008
#define VMCS_ENTRY_MSR_LOAD_ADDR        0x200A
#define VMCS_EXEC_VMCS_PTR              0x200C
#define VMCS_TSC_OFFSET                 0x2010
#define VMCS_EPT_PTR                    0x201A
#define VMCS_GUEST_PHYS_ADDR            0x2400

// 64-bit guest state
#define VMCS_GUEST_VMCS_LINK_PTR        0x2800
#define VMCS_GUEST_DEBUGCTL             0x2802
#define VMCS_GUEST_PAT                  0x2804
#define VMCS_GUEST_EFER                 0x2806
#define VMCS_GUEST_IA32_PERF_GLOBAL_CTRL 0x2808
#define VMCS_GUEST_PDPTE0              0x280A
#define VMCS_GUEST_PDPTE1              0x280C
#define VMCS_GUEST_PDPTE2              0x280E
#define VMCS_GUEST_PDPTE3              0x2810

// 64-bit host state
#define VMCS_HOST_PAT                   0x2C00
#define VMCS_HOST_EFER                  0x2C02
#define VMCS_HOST_IA32_PERF_GLOBAL_CTRL 0x2C04

// 32-bit control
#define VMCS_PIN_BASED_CONTROLS         0x4000
#define VMCS_PROC_BASED_CONTROLS        0x4002
#define VMCS_EXCEPTION_BITMAP           0x4004
#define VMCS_PF_ERROR_CODE_MASK         0x4006
#define VMCS_PF_ERROR_CODE_MATCH        0x4008
#define VMCS_CR3_TARGET_COUNT           0x400A
#define VMCS_EXIT_CONTROLS              0x400C
#define VMCS_EXIT_MSR_STORE_COUNT       0x400E
#define VMCS_EXIT_MSR_LOAD_COUNT        0x4010
#define VMCS_ENTRY_CONTROLS             0x4012
#define VMCS_ENTRY_MSR_LOAD_COUNT       0x4014
#define VMCS_ENTRY_INTERRUPTION_INFO    0x4016
#define VMCS_ENTRY_EXCEPTION_ERROR      0x4018
#define VMCS_ENTRY_INSTR_LENGTH         0x401A
#define VMCS_TPR_THRESHOLD              0x401C
#define VMCS_PROC_BASED_CONTROLS2       0x401E

// 32-bit read-only
#define VMCS_VM_INSTR_ERROR             0x4400
#define VMCS_EXIT_REASON                0x4402
#define VMCS_EXIT_INTERRUPTION_INFO     0x4404
#define VMCS_EXIT_INTERRUPTION_ERROR    0x4406
#define VMCS_IDT_VECTORING_INFO         0x4408
#define VMCS_IDT_VECTORING_ERROR        0x440A
#define VMCS_EXIT_INSTR_LENGTH          0x440C
#define VMCS_EXIT_INSTR_INFO            0x440E

// 32-bit guest state
#define VMCS_GUEST_ES_LIMIT             0x4800
#define VMCS_GUEST_CS_LIMIT             0x4802
#define VMCS_GUEST_SS_LIMIT             0x4804
#define VMCS_GUEST_DS_LIMIT             0x4806
#define VMCS_GUEST_FS_LIMIT             0x4808
#define VMCS_GUEST_GS_LIMIT             0x480A
#define VMCS_GUEST_LDTR_LIMIT           0x480C
#define VMCS_GUEST_TR_LIMIT             0x480E
#define VMCS_GUEST_GDTR_LIMIT           0x4810
#define VMCS_GUEST_IDTR_LIMIT           0x4812
#define VMCS_GUEST_ES_ACCESS            0x4814
#define VMCS_GUEST_CS_ACCESS            0x4816
#define VMCS_GUEST_SS_ACCESS            0x4818
#define VMCS_GUEST_DS_ACCESS            0x481A
#define VMCS_GUEST_FS_ACCESS            0x481C
#define VMCS_GUEST_GS_ACCESS            0x481E
#define VMCS_GUEST_LDTR_ACCESS          0x4820
#define VMCS_GUEST_TR_ACCESS            0x4822
#define VMCS_GUEST_INTERRUPTIBILITY     0x4824
#define VMCS_GUEST_ACTIVITY_STATE       0x4826
#define VMCS_GUEST_SMBASE               0x4828
#define VMCS_GUEST_SYSENTER_CS          0x482A
#define VMCS_GUEST_PREEMPT_TIMER        0x482E

// 32-bit host state
#define VMCS_HOST_SYSENTER_CS           0x4C00

// Natural-width control
#define VMCS_CR0_GUEST_HOST_MASK        0x6000
#define VMCS_CR4_GUEST_HOST_MASK        0x6002
#define VMCS_CR0_READ_SHADOW            0x6004
#define VMCS_CR4_READ_SHADOW            0x6006
#define VMCS_CR3_TARGET_VALUE0          0x6008

// Natural-width read-only
#define VMCS_EXIT_QUALIFICATION         0x6400
#define VMCS_IO_RCX                     0x6402
#define VMCS_IO_RSI                     0x6404
#define VMCS_IO_RDI                     0x6406
#define VMCS_IO_RIP                     0x6408
#define VMCS_GUEST_LINEAR_ADDR          0x640A

// Natural-width guest state
#define VMCS_GUEST_CR0                  0x6800
#define VMCS_GUEST_CR3                  0x6802
#define VMCS_GUEST_CR4                  0x6804
#define VMCS_GUEST_ES_BASE              0x6806
#define VMCS_GUEST_CS_BASE              0x6808
#define VMCS_GUEST_SS_BASE              0x680A
#define VMCS_GUEST_DS_BASE              0x680C
#define VMCS_GUEST_FS_BASE              0x680E
#define VMCS_GUEST_GS_BASE              0x6810
#define VMCS_GUEST_LDTR_BASE            0x6812
#define VMCS_GUEST_TR_BASE              0x6814
#define VMCS_GUEST_GDTR_BASE            0x6816
#define VMCS_GUEST_IDTR_BASE            0x6818
#define VMCS_GUEST_DR7                  0x681A
#define VMCS_GUEST_RSP                  0x681C
#define VMCS_GUEST_RIP                  0x681E
#define VMCS_GUEST_RFLAGS               0x6820
#define VMCS_GUEST_PENDING_DBG_EXCEPT   0x6822
#define VMCS_GUEST_SYSENTER_ESP         0x6824
#define VMCS_GUEST_SYSENTER_EIP         0x6826

// Natural-width host state
#define VMCS_HOST_CR0                   0x6C00
#define VMCS_HOST_CR3                   0x6C02
#define VMCS_HOST_CR4                   0x6C04
#define VMCS_HOST_FS_BASE               0x6C06
#define VMCS_HOST_GS_BASE               0x6C08
#define VMCS_HOST_TR_BASE               0x6C0A
#define VMCS_HOST_GDTR_BASE             0x6C0C
#define VMCS_HOST_IDTR_BASE             0x6C0E
#define VMCS_HOST_SYSENTER_ESP          0x6C10
#define VMCS_HOST_SYSENTER_EIP          0x6C12
#define VMCS_HOST_RSP                   0x6C14
#define VMCS_HOST_RIP                   0x6C16

// ── Exit reasons ────────────────────────────────────────────────────────────

#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXT_INTERRUPT       1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_INIT                3
#define EXIT_REASON_SIPI                4
#define EXIT_REASON_IO_SMI              5   // I/O SMI (SDM Vol 3C, basic exit reasons)
#define EXIT_REASON_SMI                 6   // other SMI
#define EXIT_REASON_PENDING_INTERRUPT   7   // interrupt window
#define EXIT_REASON_NMI_WINDOW          8
#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_GETSEC              11
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_RSM                 17
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMXOFF              26
#define EXIT_REASON_VMXON               27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO                  30
#define EXIT_REASON_RDMSR               31
#define EXIT_REASON_WRMSR               32
#define EXIT_REASON_INVALID_GUEST       33
#define EXIT_REASON_MSR_LOADING         34
#define EXIT_REASON_MWAIT               36
#define EXIT_REASON_MTF                 37
#define EXIT_REASON_MONITOR             39
#define EXIT_REASON_PAUSE               40
#define EXIT_REASON_MCE_DURING_ENTRY    41
#define EXIT_REASON_TPR_BELOW           43
#define EXIT_REASON_APIC_ACCESS         44
#define EXIT_REASON_VIRTUALIZED_EOI     45
#define EXIT_REASON_GDTR_IDTR           46
#define EXIT_REASON_LDTR_TR             47
#define EXIT_REASON_EPT_VIOLATION       48
#define EXIT_REASON_EPT_MISCONFIG       49
#define EXIT_REASON_INVEPT              50
#define EXIT_REASON_RDTSCP              51
#define EXIT_REASON_PREEMPT_TIMER       52
#define EXIT_REASON_INVVPID             53
#define EXIT_REASON_WBINVD              54
#define EXIT_REASON_XSETBV              55
#define EXIT_REASON_APIC_WRITE          56
#define EXIT_REASON_RDRAND              57
#define EXIT_REASON_INVPCID             58
#define EXIT_REASON_VMFUNC              59
#define EXIT_REASON_ENCLS               60
#define EXIT_REASON_RDSEED              61
#define EXIT_REASON_PML_FULL            62
#define EXIT_REASON_XSAVES              63
#define EXIT_REASON_XRSTORS             64
#define EXIT_REASON_PCONFIG             65
#define EXIT_REASON_SPP_EVENT           66
#define EXIT_REASON_UMWAIT              67
#define EXIT_REASON_TPAUSE              68
#define EXIT_REASON_LOADIWKEY           69
#define EXIT_REASON_ENCLV               70
#define EXIT_REASON_ENQCMD              71
#define EXIT_REASON_ENQCMDS             72
#define EXIT_REASON_BUS_LOCK            73
#define EXIT_REASON_INSTRUCTION_TIMEOUT 74
#define EXIT_REASON_NOTIFICATION        75
#define EXIT_REASON_WRMSRNS             77

// ── Pin-based VM-execution controls ─────────────────────────────────────────

#define PIN_BASED_EXT_INT_EXIT          (1U << 0)
#define PIN_BASED_NMI_EXIT              (1U << 3)
#define PIN_BASED_VIRTUAL_NMI           (1U << 5)
#define PIN_BASED_PREEMPT_TIMER         (1U << 6)

// ── Primary processor-based VM-execution controls ───────────────────────────

#define PROC_BASED_INT_WINDOW_EXIT      (1U << 2)
#define PROC_BASED_USE_TSC_OFFSET       (1U << 3)
#define PROC_BASED_HLT_EXIT             (1U << 7)
#define PROC_BASED_INVLPG_EXIT          (1U << 9)
#define PROC_BASED_MWAIT_EXIT           (1U << 10)
#define PROC_BASED_RDPMC_EXIT           (1U << 11)
#define PROC_BASED_RDTSC_EXIT           (1U << 12)
#define PROC_BASED_CR3_LOAD_EXIT        (1U << 15)
#define PROC_BASED_CR3_STORE_EXIT       (1U << 16)
#define PROC_BASED_CR8_LOAD_EXIT        (1U << 19)
#define PROC_BASED_CR8_STORE_EXIT       (1U << 20)
#define PROC_BASED_TPR_SHADOW           (1U << 21)
#define PROC_BASED_NMI_WINDOW_EXIT      (1U << 22)
#define PROC_BASED_MOV_DR_EXIT          (1U << 23)
#define PROC_BASED_UNCOND_IO_EXIT       (1U << 24)
#define PROC_BASED_USE_IO_BITMAPS       (1U << 25)
#define PROC_BASED_MONITOR_TRAP         (1U << 27)
#define PROC_BASED_USE_MSR_BITMAPS      (1U << 28)
#define PROC_BASED_MONITOR_EXIT         (1U << 29)
#define PROC_BASED_PAUSE_EXIT           (1U << 30)
#define PROC_BASED_ACTIVATE_SECONDARY   (1U << 31)

// ── Secondary processor-based VM-execution controls ─────────────────────────

#define PROC2_VIRT_APIC_ACCESS          (1U << 0)
#define PROC2_ENABLE_EPT                (1U << 1)
#define PROC2_DESC_TABLE_EXIT           (1U << 2)
#define PROC2_ENABLE_RDTSCP             (1U << 3)
#define PROC2_VIRT_X2APIC               (1U << 4)
#define PROC2_ENABLE_VPID               (1U << 5)
#define PROC2_WBINVD_EXIT               (1U << 6)
#define PROC2_UNRESTRICTED_GUEST        (1U << 7)
#define PROC2_APIC_REG_VIRT             (1U << 8)
#define PROC2_VIRTUAL_INT_DELIVERY      (1U << 9)
#define PROC2_PAUSE_LOOP_EXIT           (1U << 10)
#define PROC2_ENABLE_INVPCID            (1U << 12)
#define PROC2_ENABLE_VMFUNC             (1U << 13)
#define PROC2_ENABLE_XSAVES            (1U << 20)

// ── VM-exit controls ────────────────────────────────────────────────────────

#define EXIT_CTRL_SAVE_DBG_CTRL             (1U << 2)
#define EXIT_CTRL_HOST_ADDR_SPACE_SIZE      (1U << 9)
#define EXIT_CTRL_LOAD_PERF_GLOBAL_CTRL     (1U << 12)
#define EXIT_CTRL_ACK_INT_ON_EXIT           (1U << 15)
#define EXIT_CTRL_SAVE_PAT                  (1U << 18)
#define EXIT_CTRL_LOAD_PAT                  (1U << 19)
#define EXIT_CTRL_SAVE_EFER                 (1U << 20)
#define EXIT_CTRL_LOAD_EFER                 (1U << 21)
#define EXIT_CTRL_SAVE_PREEMPT_TIMER        (1U << 22)

// ── VM-entry controls ───────────────────────────────────────────────────────

#define ENTRY_CTRL_LOAD_DBG_CTRL        (1U << 2)
#define ENTRY_CTRL_IA32E_MODE_GUEST     (1U << 9)
#define ENTRY_CTRL_LOAD_PERF_GLOBAL_CTRL (1U << 13)
#define ENTRY_CTRL_LOAD_PAT             (1U << 14)
#define ENTRY_CTRL_LOAD_EFER            (1U << 15)

// ── EPT definitions ─────────────────────────────────────────────────────────

#define EPT_MEMORY_TYPE_UC              0
#define EPT_MEMORY_TYPE_WB              6
#define EPT_PAGE_WALK_LENGTH_4          (3ULL << 3)

#define EPT_READ                        (1ULL << 0)
#define EPT_WRITE                       (1ULL << 1)
#define EPT_EXECUTE                     (1ULL << 2)
#define EPT_MEMORY_TYPE_SHIFT           3
#define EPT_LARGE_PAGE                  (1ULL << 7)
#define EPT_ACCESSED                    (1ULL << 8)
#define EPT_DIRTY                       (1ULL << 9)
#define EPT_RWX                         (EPT_READ | EPT_WRITE | EPT_EXECUTE)

#define EPT_DECOY_TAG                   (1ULL << 52)
#define EPT_PFN_MASK                    0x000FFFFFFFFFF000ULL

// IA32_VMX_EPT_VPID_CAP bit positions. Verified against Intel's machine-readable
// SDM header (MiniVisorPkg Externals/ia32-doc/out/ia32.h), whose
// IA32_VMX_EPT_VPID_CAP_<FIELD>_BIT macros give these values exactly.
//
// Pass 94 named them because the checks were previously written as bare magic
// numbers with prose, and prose does not fail a build. Note in particular that
// PAGE_WALK_LENGTH_4 is bit 6 and INVEPT_ALL_CONTEXTS is bit 26 (INVEPT_SINGLE_CONTEXT
// is 25) - easy to get wrong by one, and the two that were already in the code
// were CORRECT.
#define EPTCAP_EXECUTE_ONLY_PAGES              6   // 0
#define EPTCAP_PAGE_WALK_LENGTH_4              6   // 1
#define EPTCAP_MEMORY_TYPE_UNCACHEABLE         8   // 2
#define EPTCAP_MEMORY_TYPE_WRITE_BACK         14   // 3
#define EPTCAP_PDE_2MB_PAGES                  16   // 4
#define EPTCAP_PDPTE_1GB_PAGES                17   // 5  (unused: no 1 GB leaves)
#define EPTCAP_INVEPT                         20   // 6
#define EPTCAP_ADVANCED_VMEXIT_EPT_INFO       22   // 7
#define EPTCAP_INVEPT_SINGLE_CONTEXT          25   // 8
#define EPTCAP_INVEPT_ALL_CONTEXTS            26   // 9
#define EPTCAP_INVVPID                        32   // 10
#define EPTCAP_INVVPID_INDIVIDUAL_ADDRESS     40   // 11
#define EPTCAP_INVVPID_SINGLE_CONTEXT         41   // 12
#define EPTCAP_INVVPID_ALL_CONTEXTS           42   // 13

#define EPT_PML4_SHIFT                  39
#define EPT_PDPT_SHIFT                  30
#define EPT_PD_SHIFT                    21
#define EPT_PT_SHIFT                    12

// ── Why a CPU left virtualization without being asked ──────────────────────
// (Pass 94)
//
// HvExitHandler returns FALSE on several paths. The assembly stub responds by
// doing VMXOFF and resuming the guest NATIVELY - the CPU keeps running, but it
// is no longer virtualized, and nothing in that path touched the VCPU struct.
// `Launched` therefore stayed TRUE for a CPU that had left virtualization.
//
// That flag is not decorative: DevirtualizeCpuCallback branches on it, and on
// TRUE it issues the authenticated UNLOAD VMCALL. On a CPU that already did
// VMXOFF, VMCALL is executed in VMX ROOT mode, where it raises #UD - and a DXE
// #UD has no recovery, so the machine dead-loops. The scenario is reachable from
// the exit dispatcher's DEFAULT branch, i.e. from any exit reason this build
// does not model.
//
// Every FALSE return now goes through HvDevirtualizeThisCpu(), which clears the
// flags and records why, so a later teardown sees an honest CPU and skips the
// VMCALL. The cause codes exist so a boot that half-devirtualized can say which
// path did it instead of only reporting a CPU count that no longer matches.
#define HV_DEVIRT_NONE               0u  // still virtualized (the normal case)
#define HV_DEVIRT_NO_VCPU            1u  // HvGetCurrentVcpu() returned NULL
#define HV_DEVIRT_UNKNOWN_REASON     2u  // default: exit reason not modelled
#define HV_DEVIRT_EPT_MISCONFIG      3u
#define HV_DEVIRT_TRIPLE_FAULT       4u
#define HV_DEVIRT_INVALID_GUEST      5u
#define HV_DEVIRT_MCE_DURING_ENTRY   6u
#define HV_DEVIRT_UNLOAD             7u  // UNLOAD hypercall succeeded
#define HV_DEVIRT_MSR_LOADING        8u  // VM-entry failure due to MSR loading
#define HV_DEVIRT_VMENTRY_FAIL       9u  // VM-entry failure (exit reason bit 31 set)


#define EPT_ENTRY_MASK                  0x1FF

// ── Hypercall interface ─────────────────────────────────────────────────────

// No fixed boot magic: DETECT authenticates against HvBootMagic(ticket),
// a ticket-derived value computed at load time and stored in the secrets page.
#define HV_HYPERCALL_DETECT             0x0000
#define HV_HYPERCALL_READ_PHYS          0x0001
#define HV_HYPERCALL_WRITE_PHYS         0x0002
#define HV_HYPERCALL_TRANSLATE          0x0003
#define HV_HYPERCALL_GET_CR3            0x0004
#define HV_HYPERCALL_UNLOAD             0x0005
#define HV_HYPERCALL_QUERY_STATUS       0x0006
#define HV_HYPERCALL_INVALIDATE_EPT     0x0007
#define HV_HYPERCALL_SELFTEST           0x0008
#define HV_HYPERCALL_SET_CR3_OFFSET     0x0009
#define HV_HYPERCALL_READ_SCATTER       0x000A  // reserved — not yet implemented
#define HV_HYPERCALL_CAPABILITIES       0x000B  // authenticated — ABI version + supported opcode bitmask
#define HV_ABI_VERSION                  1
#if DBG
#define HV_HYPERCALL_QUERY_EXIT_COUNTS  0x000C  // debug-only — copy ExitCounts[64] to guest buffer
#endif
// Read B1's pre-VMXON CPUID latency measurement. Not under #if DBG: the
// calibration runs in release builds too, and a harness comparing timing
// against the driver's own baseline needs it in the build that ships.
// Wire format (packed p50/p99/target/jitter) and rationale: hv_contract.h.
#define HV_HYPERCALL_QUERY_CPID_PAD     0x000D  // returns the packed pad calibration
#define HV_HYPERCALL_READ_VIRT          0x000E  // p1=pid|(size<<32), p2=srcVa, p3=dstUserVa
#define HV_HYPERCALL_WRITE_VIRT         0x000F  // p1=pid|(size<<32), p2=dstVa, p3=srcUserVa
#define HV_HYPERCALL_GET_KERNEL_BASE    0x0010  // no args; returns ntoskrnl base GVA
#define HV_HYPERCALL_QUERY_EXIT_TELEMETRY 0x0011 // p1=userVa, p2=maxRecords; returns record count
#define HV_HYPERCALL_GET_TOKEN          0x0012  // p1=pid; returns EPROCESS.Token value
#define HV_HYPERCALL_EPT_HOOK           0x0013  // p1=targetGVA, p2=hookBytesVA, p3=hookLen
#define HV_HYPERCALL_EPT_UNHOOK         0x0014  // p1=targetGVA

typedef struct {
    UINT64 Va;      // guest virtual address of destination buffer
    UINT32 Size;    // bytes to copy (must be <= PAGE_SIZE)
    UINT32 Pad;     // reserved; must be zero
} HV_READ_DESC;
#define HV_SCATTER_MAX_DESCS  64

// INVEPT / INVVPID types (Intel SDM Vol 3, 28.3 / 28.4)
//
// INVVPID is NOT numbered like INVEPT: 0=individual-address, 1=single-context,
// 2=all-context, 3=single-context retaining globals. The previous values (2/3)
// named the wrong operations, so the INVVPID fallback in HvEptInvalidate asked
// for "single-context, retaining globals" with VPID 0 — which is the root
// context — and failed instead of flushing anything.
#define INVEPT_SINGLE_CONTEXT                 1
#define INVEPT_ALL_CONTEXTS                   2
#define INVVPID_INDIVIDUAL_ADDRESS            0
#define INVVPID_SINGLE_CONTEXT                1
#define INVVPID_ALL_CONTEXTS                  2
#define INVVPID_SINGLE_CONTEXT_RETAIN_GLOBALS 3

#define HV_STATUS_CPU_MASK              0xFFFFULL
#define HV_STATUS_RUNNING_BIT           (1ULL << 16)
#define HV_STATUS_DARK_REASON_SHIFT     17
#define HV_STATUS_TSC_SHIFT             32

// The return codes live in hv_status.h so the user-mode client can read the
// same ones; they were duplicated here and invisible to Hypervisor/.
#include "../hv_status.h"

// ── Copy-loop status mapping ────────────────────────────────────────────────
// HvCopyPhysical (hv_copy.h) reports a page-wise copy as HV_COPY_STATUS; a
// hypercall reports it as one of the codes above. This build has no
// mappable-failure path (PhysToVirt cannot fail), so the only outcomes are a
// completed copy and a denied access; the size and user-range checks in
// HcReadPhysical/HcWritePhysical produce HV_STATUS_INVALID_PARAM before the loop
// is ever entered. Pinned by tools/unit/hvcopy_efi_test.c.

static __inline UINT64 HvCopyStatusToHvStatus(HV_COPY_STATUS st) {
    return st == HvCopyOk ? HV_STATUS_SUCCESS : HV_STATUS_ACCESS_DENIED;
}

// ── Per-CPU structures ──────────────────────────────────────────────────────

typedef struct _VMXON_REGION {
    UINT32 RevisionId;
    UINT8  Data[4092];
} VMXON_REGION, *PVMXON_REGION;

typedef struct _VMCS_REGION {
    UINT32 RevisionId;
    UINT32 AbortIndicator;
    UINT8  Data[4088];
} VMCS_REGION, *PVMCS_REGION;

typedef struct _GUEST_REGS {
    UINT64 Rax;
    UINT64 Rcx;
    UINT64 Rdx;
    UINT64 Rbx;
    UINT64 Rsp;
    UINT64 Rbp;
    UINT64 Rsi;
    UINT64 Rdi;
    UINT64 R8;
    UINT64 R9;
    UINT64 R10;
    UINT64 R11;
    UINT64 R12;
    UINT64 R13;
    UINT64 R14;
    UINT64 R15;
} GUEST_REGS, *PGUEST_REGS;

// ── CPUID timing-pad calibration ────────────────────────────────────────────
// The CPUID exit handler pads its return so the guest observes roughly
// bare-metal CPUID latency. A single constant floor is itself a fingerprint:
// a detector sampling thousands of iterations sees a real CPUID distribution
// with spread, not "never faster than N". HvCalibrateCpuidLatency() therefore
// measures this silicon's p99 before any VMXON and the handler pads to that
// plus a jitter margin. The defaults reproduce the historical
// `entryTsc + 200` and are also the fallback when calibration is skipped or
// the measurement is implausible.
#define HV_CPUID_PAD_DEFAULT_TARGET  200   // today's fixed floor / fallback
#define HV_CPUID_PAD_DEFAULT_JITTER  0     // today's fixed floor / fallback
#define HV_CPUID_PAD_MIN             64    // below this: CPUID did not execute
#define HV_CPUID_PAD_MAX             1024  // above this: CPUID is being trapped
#define HV_CPUID_PAD_SAMPLES         512   // stable p99: index 506/512

#define HV_CPUID_CACHE_SIZE  16

typedef struct _HV_CPUID_CACHE_ENTRY {
    UINT32 Leaf;
    UINT32 SubLeaf;
    UINT32 Valid;
    UINT32 Regs[4];
} HV_CPUID_CACHE_ENTRY, *PHV_CPUID_CACHE_ENTRY;

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

typedef struct _VCPU {
    PVMXON_REGION VmxonRegion;
    LARGE_INTEGER VmxonPhysical;

    PVMCS_REGION  VmcsRegion;
    LARGE_INTEGER VmcsPhysical;

    PVOID         MsrBitmap;
    LARGE_INTEGER MsrBitmapPhysical;

    PVOID         HostStack;
    SIZE_T        HostStackSize;

    HV_TSS64      Tss;

    GUEST_REGS    GuestRegs;

    BOOLEAN       Launched;
    BOOLEAN       VmxEnabled;
    UINT32        ProcessorIndex;

    // HV_DEVIRT_* : why this CPU left virtualization on its own, 0 while it
    // is still covered. Written by the exit handler before every FALSE
    // return so DevirtualizeCpuCallback never VMCALLs a CPU that has
    // already VMXOFF'd (that is #UD in root mode - an unrecoverable DXE
    // hang). See the HV_DEVIRT_* block above.
    UINT32        DevirtCause;

    // Why bring-up failed for THIS cpu, 0 while it never failed. The
    // driver has one mailbox slot shared by every AP, so before Pass 94 a
    // multi-CPU failure raced on it and the receipt named an arbitrary
    // CPU. The per-CPU copy is the record; the mailbox carries only a
    // summary. Packed with HvStage12DetailEncode() so the value is
    // meaningful to tools/diag without a private format.
    UINT32        LaunchError;

    // APIC ID recorded once at bring-up. After ExitBootServices gEfiMp is gone,
    // so the runtime exit path (every VM exit) resolves the current VCPU by
    // matching this against the live APIC ID instead of calling WhoAmI.
    UINT32        ApicId;

    // Emulated guest CR8 (TPR). CR8 is not a VMCS field, so a forced
    // CR8-load/CR8-store exit cannot be satisfied with __writecr8/__readcr8:
    // those touch the HOST's CR8 (the current IRQL) mid-handler. The guest's
    // value lives here instead, initialised to 0 at vCPU setup.
    UINT64        GuestCr8;

    // NOTE: no IA32_TSC_ADJUST shadow. It passes through to hardware untouched:
    // the MSR is added to every later RDTSC, so a shadow would let a guest see
    // RDMSR round-trip while RDTSC stood still — a two-instruction VM test.

    HV_CPUID_CACHE_ENTRY CpuidCache[HV_CPUID_CACHE_SIZE];

    // The EPT mutation generation this processor last invalidated for,
    // compared against g_Hv.EptGeneration at every VM-exit entry. A processor
    // that is behind is running with cached translations taken before an EPT
    // change, and a VM exit is the only context in which it can put itself
    // right - it is executing the guest (VMX non-root) at every other moment,
    // and INVEPT there is #UD. See ../hv_ept_gen.h.
    LONG          EptSeenGeneration;

    // Epoch-tagged slot reference for the pending MTF restore (HvHookTagMake).
    // An index on its own is not enough once slots are reusable - see
    // ../hv_hookpool.h.
    UINT64        MtfHookTag;
    BOOLEAN       MtfRestorePending;
} VCPU, *PVCPU;

// ── Devirtualization snapshot (EFI build) ───────────────────────────────────
//
// VM-exit stub HvAsmVmxEntry snapshots the VMCS guest state while still in VMX
// operation, issues VMXOFF, then hands this struct to HvCaptureUnloadState /
// HvUnloadRestoreState (hv_efi_smp.c) to put the CPU back exactly where the
// guest was. The DXE build needs the full snapshot because it devirtualizes
// before ExitBootServices, where the descriptor tables and control registers
// come from firmware state that no longer exists afterwards.
//
// FIELD ORDER IS LOAD-BEARING. HvEfi/hv_asm.asm indexes this struct by literal
// byte offsets (HV_US_* EQUs) and reserves HV_UNLOAD_STATE_SIZE (184) bytes on
// the host stack for it, so reordering, adding or removing a field silently
// corrupts the restored guest. Both invariants are asserted: the size by the
// STATIC_ASSERT in hv_efi_smp.c, the offsets by the comments below.
//
// The WDK tree has no equivalent: HvDrv/hv_asm.asm restores CR3/RSP/RIP/RFLAGS
// straight from the stack and needs no struct. The two assembly files are
// deliberately not identical — see the note in tools/syntax-check/run.sh.
typedef struct _HV_UNLOAD_STATE {
    UINT64 Cr3;        // +0    HV_US_CR3
    UINT64 Rip;        // +8    HV_US_RIP
    UINT64 Rsp;        // +16   HV_US_RSP
    UINT64 CsSel;      // +24   HV_US_CSSEL
    UINT64 GdtrBase;   // +32
    UINT64 GdtrLimit;  // +40
    UINT64 IdtrBase;   // +48
    UINT64 IdtrLimit;  // +56
    UINT64 DsSel;      // +64
    UINT64 EsSel;      // +72
    UINT64 FsSel;      // +80
    UINT64 GsSel;      // +88
    UINT64 SsSel;      // +96
    UINT64 TrSel;      // +104
    UINT64 LdtrSel;    // +112
    UINT64 FsBase;     // +120
    UINT64 GsBase;     // +128
    UINT64 Pat;        // +136
    UINT64 Efer;       // +144
    UINT64 Rflags;     // +152  HV_US_RFLAGS
    UINT64 Cr0;        // +160
    UINT64 Cr4;        // +168
    UINT64 Dr7;        // +176
} HV_UNLOAD_STATE, *PHV_UNLOAD_STATE;   // 23 x 8 = 184 bytes

#define HV_UNLOAD_STATE_SIZE 184

// ── EPT structures ──────────────────────────────────────────────────────────

#define HV_MAX_HIDDEN_PAGES 4096
#define HV_DECOY_COUNT      8
#define HV_MAX_SPLIT_PAGES  HV_MAX_HIDDEN_PAGES
#define HV_MAX_EPT_HOOKS    16

#define EPROCESS_TOKEN_OFFSET 0x4B8

#define HV_MAX_RAM_RANGES   128

// Maximum 512GB PML4 units the EPT identity-maps. Unit 0 (the low 512GB) is
// always mapped; further units cover RAM that reports above 512GB. Capped so a
// bogus memory map cannot make init allocate unbounded EPT metadata.
#define HV_MAX_EPT_PML4_UNITS 64

typedef union _EPT_PTE {
    UINT64 Value;
    struct {
        UINT64 Read        : 1;
        UINT64 Write       : 1;
        UINT64 Execute     : 1;
        UINT64 MemoryType  : 3;
        UINT64 IgnorePat   : 1;
        UINT64 LargePage   : 1;
        UINT64 Accessed    : 1;
        UINT64 Dirty       : 1;
        UINT64 Reserved0   : 2;
        UINT64 PhysAddr    : 40;
        UINT64 Reserved1   : 12;
    };
} EPT_PTE, *PEPT_PTE;

typedef struct _HV_EPT_HOOK {
    UINT64   TargetGpa;
    UINT64   ShadowPagePa;
    UINT64   OrigPteValue;
    PEPT_PTE PtePtr;
    // The 2MB region this page sits in and the shadow-pool entry backing it,
    // so removal can give both back without a search. RegionBase is what lets
    // the last hook to leave a split region collapse it again.
    UINT64   RegionBase;
    UINT32   ShadowSlot;
    // Install epoch, carried in the pending-MTF tag (HvHookTagMake) so a slot
    // recycled by a later hook cannot be restored by the earlier one's
    // single-step. See ../hv_hookpool.h.
    UINT32   Epoch;
    UINT32   Active;
    UINT32   Pad;
} HV_EPT_HOOK;

// Hypercall/EPT contract shared verbatim with the WDK build (HvValidateCopyU64,
// HvHypercallCodeKnown, HvEptPml4Units, HvScatterValidate).
//
// It MUST be included before EPT_STATE: that struct embeds HV_MTRR_STATE, which
// this header defines. It sits here because every constant the contract needs
// (PAGE_SIZE, PHYSICAL_MEMORY_RANGE, EPT_PML4_SHIFT, EPT_MEMORY_TYPE_*,
// HV_MAX_EPT_PML4_UNITS, HV_STATUS_*, HV_HYPERCALL_*) is already defined above
// this point. Previously the include was placed after EPT_STATE, which left
// HV_MTRR_STATE undeclared at the point of use and made the driver uncompilable.
#include "../hv_contract.h"
#include "../hv_ramrange.h"
// hv_ramrange.h must precede EPT_STATE above: NormRanges[] is an HV_RANGE[].

typedef struct _EPT_STATE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PTE Pml4[512];
    // One PDPT page per mapped 512GB unit; Pml4[u] points at PdptVa[u].
    PEPT_PTE  PdptVa[HV_MAX_EPT_PML4_UNITS];
    PEPT_PTE *PdptPages;       // flat array of PD page VAs, indexed by (pa >> 30)
    UINT32    PdptCount;       // mapped 1GB units == PdptUnitCount * 512
    UINT32    PdptUnitCount;
    UINT64    EptPointer;

    PHYSICAL_MEMORY_RANGE RamRanges[HV_MAX_RAM_RANGES];
    UINT32    RamRangeCount;

    // Normalised view of RamRanges[]: base-sorted AND end-monotone, built
    // once by HvRamRangeNormalize() so the EPT region predicates can be
    // plain binary searches. RamRanges[] stays as the raw firmware map
    // because HvEptPml4Units() and the shared host-map snapshot read it.
    // Pass 94: the old search assumed monotone ends, which base-sorted
    // order does NOT imply, so a legal memory map could get real RAM
    // mapped UC - and UC RAM is the infinite-#PF-loop brick.
    HV_RANGE  NormRanges[HV_MAX_RAM_RANGES];
    UINT32    NormRangeCount;

    // MTRR snapshot for memory-type validation (HvMtrrInitialize).
    // EptMemTypeForPa intersects this with RamRanges: MTRR non-WB
    // wins over RAM-map WB (MMIO wins -> UC), fail closed to UC.
    HV_MTRR_STATE Mtrr;

    // SplitOriginalPd[i] is the PD entry EptSplitLargePage replaced, saved so
    // unhide can collapse the region back to its original 2MB large page. 0 for
    // an init-time mixed region, whose PD entry must stay pointing at its PT.
    PEPT_PTE  SplitPages[HV_MAX_SPLIT_PAGES];
    UINT64    SplitRegionBase[HV_MAX_SPLIT_PAGES];
    UINT64    SplitOriginalPd[HV_MAX_SPLIT_PAGES];
    UINT32    SplitCount;

    // Region split claim: the tag (HvSplitRegionTag) of the region whose split
    // is in flight, 0 when none is. It is what makes the split record appear
    // exactly once per region when two processors both find the region still a
    // large page - see the claim note in ../hv_hookpool.h. Cast to
    // `volatile long *` at the call sites: EDK2's LONG is `int`, and the
    // intrinsic is declared for `long`.
    volatile LONG SplitClaim;
} EPT_STATE, *PEPT_STATE;

// ── Global hypervisor state ─────────────────────────────────────────────────

typedef struct _HV_SECRETS {
    UINT64 SessionKey0;
    UINT64 SessionKey1;
    UINT64 SessionMagic;
    UINT64 BootMagic;
    UINT64 UnloadMac;
    volatile LONG64 LastSeq;
} HV_SECRETS, *PHV_SECRETS;

// Hypercall authentication (secrets-injected so it can run off-target). Placed
// after HV_SECRETS and the HV_STATUS_* codes, which it uses.
#include "../hv_auth.h"

// The shared contract is included above, before EPT_STATE (see the note there).
#include "../hv_segs.h"

// ── VMCS write with failure check ───────────────────────────────────────────
// HvVmWriteChecked/HvVmWriteLog need a fatal logger. hv_efi.h defines EfiFatal
// (DEBUG-based), but shared TUs like hv_exit.c include only this header by
// design — without this fallback they fail to compile (EfiFatal undefined).
#ifndef EfiFatal
#include <Library/DebugLib.h>
#define EfiFatal(fmt, ...) DEBUG((DEBUG_ERROR, "[FATAL] " fmt, ##__VA_ARGS__))
#endif
#define HvVmWriteChecked(field, value) \
    do { \
        if (__vmx_vmwrite((UINT32)(field), (UINT64)(value)) != 0) { \
            EfiFatal("HvVmcs: vmwrite field 0x%x failed\n", (UINT32)(field)); \
            return STATUS_UNSUCCESSFUL; \
        } \
    } while(0)

// Log-only variant for exit-handler paths where we cannot return a status.
#define HvVmWriteLog(field, value) \
    do { \
        if (__vmx_vmwrite((UINT32)(field), (UINT64)(value)) != 0) { \
            EfiFatal("HvExit: vmwrite field 0x%x failed (continuing)\n", (UINT32)(field)); \
        } \
    } while(0)

// ── Portable randomness (CPUID-gated RDRAND with TSC fallback) ──────────────
// RDRAND was introduced with Ivy Bridge (2012). On any CPU that lacks it the
// instruction raises #UD, which is a fatal trap in an EFI driver.
// Always call HvRandomU64() rather than _rdrand64_step() directly.
static inline BOOLEAN HvCpuHasRdrand(void) {
    int regs[4] = {0};
    __cpuid(regs, 1);
    return (regs[2] >> 30) & 1;   // ECX bit 30
}

static inline UINT64 HvRandomU64(void) {
    unsigned __int64 v = 0;
    if (HvCpuHasRdrand() && _rdrand64_step(&v)) return v;
    // TSC fallback: mix in IA32_TSC_AUX (CPU-id written by the OS) for extra entropy.
    return (UINT64)__rdtsc() ^ (UINT64)(UINTN)&v ^
           (UINT64)__readmsr(0xC0000103UL);  // IA32_TSC_AUX
}

// Key-material randomness: RDRAND only, fail closed. The TSC fallback in
// HvRandomU64 is fine for nonces that only need uniqueness, but not for key
// material — the TSC is guest-observable and low-entropy, so a predictable
// "random" value here would weaken the session keys and the pointer
// obfuscation. Callers that derive keys must refuse to start when this
// returns FALSE (no RDRAND CPUID support, or repeated transient failure).
static inline BOOLEAN HvRandomKeyU64(UINT64 *out) {
    if (!HvCpuHasRdrand()) return FALSE;
    // RDRAND can fail transiently under contention; the SDM recommends
    // retrying (up to ~10 times) before treating it as a hard failure.
    for (int i = 0; i < 10; i++) {
        unsigned __int64 v = 0;
        if (_rdrand64_step(&v)) {
            *out = v;
            return TRUE;
        }
    }
    return FALSE;
}

// Reason the hypervisor entered dark mode (Phase C).
typedef enum _HV_DARK_REASON {
    HV_DARK_NONE               = 0,
    HV_DARK_SELFTEST_FAIL      = 1,
    HV_DARK_PARTIAL_LAUNCH     = 2,
    HV_DARK_ZERO_LAUNCH        = 3,
    HV_DARK_ILLEGAL_TRANSITION = 4,
} HV_DARK_REASON;

// Explicit lifecycle state for the hypervisor (Phase B).
typedef enum _HV_STATE {
    HV_STATE_INIT       = 0,
    HV_STATE_VMX_READY  = 1,
    HV_STATE_HIDDEN     = 2,
    HV_STATE_RUNNING    = 3,
    HV_STATE_DARK       = 4,
    HV_STATE_UNLOADING  = 5,
    HV_STATE_SHUTDOWN   = 6,
} HV_STATE;

typedef struct _HV_GLOBAL {
    PVCPU       Vcpus;
    UINT32      VcpuCount;
    UINT32      VcpusPageCount;
    EPT_STATE   Ept;
    volatile HV_STATE State;      // authoritative lifecycle state (Phase B)
    HV_DARK_REASON    DarkReason; // why dark mode was entered (Phase C)
    BOOLEAN     Running;          // legacy shim: TRUE when State == HV_STATE_RUNNING
    BOOLEAN     Dark;             // legacy shim: TRUE when State == HV_STATE_DARK
    UINT32      VmxRevisionId;

    UINT64      Nonce;

    PVOID       SecretsPageVa;
    UINT64      SecretsPagePa;
    UINT64      CleanupKey;
    BOOLEAN     PointersObfuscated;

    // AP bring-up hand-off. CbInFlight counts VirtualizeCpuCallback bodies
    // currently executing on ANY cpu; it is bracketed by the callback on entry
    // and every exit path. TeardownUnsafe is set when a bring-up timeout is
    // observed while CbInFlight is non-zero — meaning a peer AP may still be
    // writing VMXON/VMCS/EPT/host-stack pages that the rollback is about to
    // free. When it is set, teardown leaks those allocations instead of
    // freeing memory an AP is still using: a leak survives, a use-after-free
    // on a CPU running in VMX root faults with no handler and triple-faults.
    volatile LONG CbInFlight;
    BOOLEAN     TeardownUnsafe;

    // Spontaneous devirtualization (Pass 94). Every FALSE return from the exit
    // handler goes through HvDevirtualizeThisCpu(), which clears that CPU's
    // Launched/VmxEnabled flags and records the cause. DevirtCount is the
    // machine-wide total; DevirtNoVcpuCount counts the subset where no VCPU could
    // be resolved at all, which is the one case with nowhere else to record it.
    //
    // Both are LONG64 so the counters use InterlockedIncrement64, the same
    // intrinsic this file already relies on - the EFI tree typedefs LONG as
    // INT32, and casting it to the `volatile long *` the intrinsic wants is a
    // /W4 C4057. A diagnostic counter is not worth a cast.
    //
    // A non-zero DevirtCount with g_Hv.Running still TRUE is the signature of a
    // machine running under PARTIAL virtualization, which used to be
    // indistinguishable from a clean boot until teardown tried to VMCALL a
    // CPU that had already left VMX operation.
    volatile LONG64 DevirtCount;
    volatile LONG64 DevirtNoVcpuCount;


    // Per-boot random TSC base shift (Pass 62) — see HvDrv/hvdefs.h for rationale.
    INT64       TscBootOffset;

    // CPUID timing-pad calibration (B1) — written once by
    // HvCalibrateCpuidLatency() before VMXON and read-only afterwards, so the
    // per-exit pad needs no lock. UINT32 is ample for the [MIN, MAX] window.
    UINT32      CpuidPadTarget;   // measured p99 CPUID latency (or 200)
    UINT32      CpuidPadJitter;   // extra spread added per call (or 0)
    // The raw percentiles behind the two above, kept so an observer can see
    // what the pad was derived from instead of only its result. 0 when
    // calibration fell back to the defaults. Read via
    // HV_HYPERCALL_QUERY_CPID_PAD.
    UINT32      CpuidPadP50;      // median measured CPUID latency, TSC ticks
    UINT32      CpuidPadP99;      // 99th percentile measured CPUID latency

    UINT64      TscCalibBaseTsc;
    INT64       TscCalibBaseQpc;
    INT64       TscCalibQpcFreq;
    INT64       TscPerQpc256;

    // DecoyActiveCount is randomized per boot to [2, 5] to vary the EPT
    // fingerprint; the arrays are always sized HV_DECOY_COUNT maximum.
    PVOID       DecoyPageVa[HV_DECOY_COUNT];
    UINT64      DecoyPagePa[HV_DECOY_COUNT];
    UINT32      DecoyActiveCount;            // actual count used this boot

    UINT64      HiddenPages[HV_MAX_HIDDEN_PAGES];
    UINT32      HiddenPageCount;

    // EFI-specific: identity-mapped host page tables for VMX root mode.
    // HostPml4Units is the number of 512GB PML4 units mapped, matching the EPT's
    // coverage: the host dereferences guest physical addresses directly (VA ==
    // PA), so it must reach any RAM the EPT lets the guest use.
    PVOID       HostPml4Va;
    UINT64      HostPml4Pa;
    UINT32      HostPml4Units;

    // EFI-specific: CR3 offset for guest EPROCESS (configurable via hypercall)
    UINT32      DirectoryTableOffset;

    // Per-Core VMLAUNCH target count (Pass 96)
    UINT32      TargetVcpuCount;

    // Runtime VM-exit telemetry ring buffer (Pass 96)
    HV_EXIT_RECORD ExitLog[64];
    volatile LONG64 ExitLogIndex;

    // EPT mutation generation: published before every EPT entry is modified,
    // read by every processor at VM-exit entry. This is how a mapping change
    // reaches the other logical processors - an IPI cannot, because they are
    // in VMX non-root and INVEPT there is #UD. See ../hv_ept_gen.h for why
    // this is 32 bits and why the increment must be atomic.
    volatile LONG EptGeneration;

    // EPT stealth hook tracking (STUDY.md: cmpxchg16b adaptation)
    //
    // Occupancy is a MASK per pool, not a used-count. The first cut counted
    // upwards and never came back down - removal cleared only the slot's Active
    // flag - so the 16th install was the last this boot would ever do, however
    // many of them had been uninstalled. A mask records WHICH entry is free,
    // which is what makes install/uninstall cycles reuse them. Every decision
    // taken over these masks is a pure function in ../hv_hookpool.h.
    HV_EPT_HOOK EptHooks[HV_MAX_EPT_HOOKS];
    UINT32      EptHookUsedMask;
    PVOID       ShadowPagePool[HV_MAX_EPT_HOOKS];
    PVOID       SparePtPool[HV_MAX_EPT_HOOKS];
    UINT32      ShadowPageUsedMask;
    UINT32      SparePtUsedMask;
    // Monotonic install counter: stamped into the hook slot at install and into
    // the pending-MTF tag, so a recycled slot is rejected rather than restored.
    volatile LONG EptHookEpoch;

#if DBG
    // Per-exit-reason counters for performance + stealth auditing.
    volatile LONG64 ExitCounts[64];
#endif
} HV_GLOBAL, *PHV_GLOBAL;

extern HV_GLOBAL g_Hv;
#include "hv_efi_bootcfg.h"
extern volatile HV_MAILBOX *g_Mailbox;
extern UINT16 g_HvHostBaseTssSlot;

// ── Function declarations ───────────────────────────────────────────────────

// hv_efi_vmx.c
NTSTATUS HvVmxInitialize(void);
void     HvVmxShutdown(void);
BOOLEAN  HvVmxIsSupported(void);
void     HvEnterDarkMode(HV_DARK_REASON reason);
BOOLEAN  HvTransitionState(HV_STATE from, HV_STATE to);

// Measure this CPU's bare-metal CPUID latency (p99 + jitter margin) and store
// it in g_Hv.CpuidPadTarget / CpuidPadJitter. MUST run before any VMXON so the
// samples are genuinely unvirtualized; runs once on the boot CPU, so it never
// lengthens AP bring-up. Falls back to HV_CPUID_PAD_DEFAULT_* on implausible
// results. Defined in hv_exit.c.
void     HvCalibrateCpuidLatency(void);

// Recompute the exit stub's extended-state save policy from the live XCR0.
// Called at init and whenever a guest XSETBV changes XCR0; never on the
// steady-state exit path.
BOOLEAN  HvRefreshStateSaveMask(void);
BOOLEAN  HvXsaveNewBitsSavable(UINT64 newXcr0);

// hv_vmcs.c
NTSTATUS HvHostTablesInit(UINT64 firmwareGdtBase, UINT16 firmwareGdtLimit,
                         UINT16 csSelector, UINT32 vcpuCount);
void     HvHostTablesTeardown(void);
NTSTATUS HvVmcsSetupCpu(PVCPU vcpu);

// hv_efi_ept.c
NTSTATUS HvEptInitialize(PEPT_STATE ept);
void     HvEptDestroy(PEPT_STATE ept);
BOOLEAN  HvEptTranslateGpa(PEPT_STATE ept, UINT64 gpa, PUINT64 hpa);
EPT_PTE *HvEptLookup4K(PEPT_STATE ept, UINT64 gpa);
EPT_PTE *HvEptEnsure4K(PEPT_STATE ept, UINT64 gpa);
BOOLEAN  HvEptIsRamPage(PEPT_STATE ept, UINT64 gpa);
// Large-page-aware "is this GPA normal RAM" predicate (see hv_efi_ept.c).
// HvEptLookup4K returns NULL for large pages (nearly all RAM). Requires a
// readable WB leaf mapping; decoy-redirected hidden pages pass, so reject
// hypervisor-owned pages separately via HvEfiIsHypervisorPage.
NTSTATUS HvEptHidePages(PEPT_STATE ept, UINT64 *pages, UINT32 count,
                        UINT64 *decoyPas, UINT32 decoyCount);
NTSTATUS HvEptHidePagesExecutable(PEPT_STATE ept, UINT64 *pages, UINT32 count,
                                          UINT64 *decoyPas, UINT32 decoyCount);
void     HvEptUnhidePages(PEPT_STATE ept);
void     HvEptInvalidate(void);   // publish + local flush (VMX root only)
void     HvEptFlushLocal(void);   // local INVEPT only; no counter change
void     HvEptPublishMutation(void);      // counter only; safe in non-root
void     HvEptGenerationSync(PVCPU vcpu); // flush if behind; VM-exit entry
NTSTATUS HvEptInstallHook(PEPT_STATE ept, UINT64 targetGpa,
                          const UINT8 *hookBytes, UINT32 hookLen);
NTSTATUS HvEptRemoveHook(PEPT_STATE ept, UINT64 targetGpa);
UINT32   HvEptFindHook(UINT64 gpa);
// Return both pre-allocated hook pools (shadow pages and spare PT pages) to
// the firmware. Idempotent, and safe to call on a path where the pools were
// never allocated. Called from HvEptDestroy and from the driver's failure
// funnel, because bring-up can fail between pool allocation and EPT setup.
void     HvEptHookPoolsFree(void);

// hv_exit.c
BOOLEAN  HvExitHandler(PGUEST_REGS guestRegs);

// hv_efi_hypercall.c
UINT64   HvHypercallDispatch(PVCPU vcpu, UINT64 magic, UINT64 id, UINT64 p1,
                              UINT64 p2, UINT64 callerMac, UINT64 p3Real);
UINT64   HvGetSessionMagic(void);
UINT64   HvComputeUnloadMac(void);
struct _HV_SECRETS *GetSecretsPage(void);

// hv_efi_smp.c
NTSTATUS HvSmpVirtualizeAllProcessors(void);
void     HvSmpDevirtualizeAllProcessors(void);
PVCPU    HvGetCurrentVcpu(void);
// Publish an EPT mutation to every processor. Deferred by construction: it
// moves the generation forward so each processor invalidates at its own next
// VM exit. It does NOT dispatch anything to another processor - see the long
// note at the top of ../hv_ept_gen.h for why that cannot be done safely, and
// why attempting it is a freeze rather than a flush.
void     HvSmpBroadcastEptFlush(void);

// hv_asm.asm
extern void HvAsmVmxEntry(void);
extern int  HvAsmVmxLaunch(void);
extern void HvAsmVmxResume(void);
extern void HvAsmWriteCr2(UINT64 value);
extern int  HvAsmInvept(UINT64 type, void *desc);
extern int  HvAsmInvvpid(UINT64 type, void *desc);
extern void HvAsmVmcallUnload(UINT64 magic, UINT64 id,
                               UINT64 p1, UINT64 p2,
                               UINT64 mac, UINT64 p3);
extern BOOLEAN HvAsmReadMsrSafe(UINT32 msr, UINT64 *outVal);
extern BOOLEAN HvAsmWriteMsrSafe(UINT32 msr, UINT64 val);
extern void    HvAsmHostGpHandler(void);
