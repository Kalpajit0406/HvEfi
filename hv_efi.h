// hv_efi.h - EFI DXE runtime driver helpers.
//
// Provides EFI protocol wrappers, memory allocation via Boot Services,
// and serial debug output. Included by all EFI-specific .c files;
// hv_vmcs.c needs it for EfiFatal on fail-hard VMCS aborts.

#pragma once

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/MpService.h>
#include <Protocol/LoadedImage.h>
#include <Guid/GlobalVariable.h>

#include "hvdefs.h"
#include "hv_efi_stage.h"

// Post a stage byte to the POST port. Declared here rather than in
// hv_efi_main.c because the per-AP launch failure path in hv_efi_smp.c needs one
// too, and two local copies of this macro are how two POST channels start
// disagreeing (reports/review_adjudication.md, finding C6).
void __outbyte(unsigned short Port, unsigned char Data);
#define HV_POST(code) do { __outbyte(0x80, (unsigned char)(code)); } while (0)

// Stage + detail into the boot status blob, implemented in hv_efi_main.c.
// Declared here for the same reason: the AP path must report through the same
// two channels the BSP does, or "CPU 3 never launched" is indistinguishable
// from a clean stand-down.
void HvReportStage(UINT32 stage, UINT32 detail);

// ── EFI globals (set during entry, used by init code) ──────────────────────

extern EFI_BOOT_SERVICES         *gEfiBS;
extern EFI_RUNTIME_SERVICES      *gEfiRT;
extern EFI_MP_SERVICES_PROTOCOL  *gEfiMp;

// ── Debug output (available before ExitBootServices) ───────────────────────

// Guarded so hvdefs.h (included just below) can carry its own definition for
// the non-EDK2 type-check builds without redefining these here.
#ifndef EfiPrint
#define EfiPrint(fmt, ...)  DEBUG((DEBUG_INFO, fmt, ##__VA_ARGS__))
#define EfiFatal(fmt, ...)  DEBUG((DEBUG_ERROR, "[FATAL] " fmt, ##__VA_ARGS__))
#endif

// HV_LOG is the WDK tree's debug-print macro (HvDrv/hvdefs.h); the EFI tree
// never defined it, so the two uses in hv_efi_smp.c had no definition under
// EDK2. Map it to the EFI debug print. Uses are written HV_LOG(("...")) with
// double parentheses, hence the bare `x`.
#define HV_LOG(x)           EfiPrint x

// ── Physical page allocation ───────────────────────────────────────────────
// In EFI DXE, VA == PA (identity mapped).  AllocatePages returns a physical
// address that is also the virtual address.
//
// Single definition: the two historical helpers were byte-identical (both
// AllocateMaxAddress capped below 4 GB). The Below4G name is kept because it
// states the actual guarantee callers rely on — VMXON/VMCS regions must sit
// below 4 GB, and VMX root uses a conservatively mapped identity map, so
// persistent page-backed state stays in a low, always-mapped range rather
// than relying on firmware placement on high-memory systems.

static inline PVOID EfiAllocPagesBelow4G(UINT32 pageCount) {
    EFI_PHYSICAL_ADDRESS pa = 0xFFFFFFFF;
    EFI_STATUS st = gEfiBS->AllocatePages(
        AllocateMaxAddress,
        EfiRuntimeServicesData,
        pageCount,
        &pa
    );
    if (EFI_ERROR(st)) return NULL;
    ZeroMem((VOID *)(UINTN)pa, (UINTN)pageCount * PAGE_SIZE);
    return (PVOID)(UINTN)pa;
}

static inline void EfiFreePages(PVOID va, UINT32 pageCount) {
    if (va) {
        gEfiBS->FreePages((EFI_PHYSICAL_ADDRESS)(UINTN)va, pageCount);
    }
}

static inline PVOID EfiAllocPool(UINTN bytes) {
    VOID *p = NULL;
    EFI_STATUS st = gEfiBS->AllocatePool(EfiRuntimeServicesData, bytes, &p);
    if (EFI_ERROR(st)) return NULL;
    ZeroMem(p, bytes);
    return p;
}

static inline void EfiFreePool(PVOID p) {
    if (p) gEfiBS->FreePool(p);
}

// ── Physical ↔ Virtual (identity mapping) ──────────────────────────────────
// Before ExitBootServices, UEFI uses identity-mapped page tables.
// After ExitBootServices, our host CR3 uses our own identity-mapped tables.

static inline UINT64 EfiVaToPA(PVOID va) {
    return (UINT64)(UINTN)va;
}

static inline PVOID EfiPaToVa(UINT64 pa) {
    return (PVOID)(UINTN)pa;
}

// ── EFI variable helpers ───────────────────────────────────────────────────
//
// gHvVarName is a 24-wchar patchable buffer initialized with a sentinel.
// InstallEfiBinary() in hv_launcher.c scans the EFI binary for the sentinel
// pattern and overwrites it with a random name (e.g. L"HvV_A3F1B2C9") so the
// static string L"HvDrvTicket" never appears in the shipped binary.
// Sentinel bytes (UTF-16 LE): EF EF BE BE AD AD DE DE 00 00
extern CHAR16 gHvVarName[24];

// EFI GUID for the auth ticket variable. Defined as a non-const global so
// InstallEfiBinary() can patch it the same way it patches gHvVarName.
// The sentinel value below is replaced at install time with a random GUID;
// the EFI binary fails gracefully at boot if the sentinel is still present.
// Sentinel: Data1 = 0xDEADC0DE (recognizable; not a valid real GUID vendor).
extern EFI_GUID gHvTicketGuid;

// ── EPT RAM map ────────────────────────────────────────────────────────────
// Populates EPT_STATE.RamRanges[]/RamRangeCount from the EFI memory map. Shared
// by the EPT builder and the host identity-map builder so both cover exactly the
// same range — the host dereferences guest physical addresses directly, so its
// map has to reach every unit the EPT maps.

NTSTATUS HvEptCollectRamRanges(PEPT_STATE ept);

// ── Host page table builder ────────────────────────────────────────────────
// Builds identity-mapped x86-64 page tables (2MB large pages) that persist
// after ExitBootServices.  Set as HOST_CR3 in VMCS.

NTSTATUS HvBuildHostPageTables(UINT64 imageBase, UINT64 imageSize);

// Destroys the identity-mapped host page tables built above. Central teardown
// point: HvVmxShutdown calls it, so the driver-entry fail path, VMX-init
// failure, and unload all release the host map.

void HvDestroyHostPageTables(void);

// ── EFI entry/shutdown ─────────────────────────────────────────────────────

EFI_STATUS EFIAPI HvEfiDriverEntry(
    EFI_HANDLE        imageHandle,
    EFI_SYSTEM_TABLE  *systemTable
);
