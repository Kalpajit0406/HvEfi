// hv_driver.c — Windows Kernel Companion Driver for HvEfi Hypervisor
//
// Bridges Windows Ring-0 kernel and user-mode applications with the
// UEFI-resident HvEfi hypervisor via authenticated VMCALLs.

#include <ntddk.h>
#include <intrin.h>

#ifndef UINTN
typedef UINT_PTR UINTN;
#endif

#include "../../shared/hv_siphash.h"
#include "../../shared/hv_status.h"
#include "../../shared/hv_ioctl.h"

// Forward declaration of assembly stub
extern UINT64 HvAsmVmcall(UINT64 magic, UINT64 id, UINT64 p1, UINT64 p2, UINT64 mac, UINT64 p3);

// Driver globals
static PDEVICE_OBJECT g_DeviceObject = NULL;
static UNICODE_STRING g_DeviceName;
static UNICODE_STRING g_SymLinkName;

static HV_SHM_REQUEST *g_CommBuf        = NULL;
static UINT64          g_CommPA         = 0;
static HANDLE          g_ThreadHandle   = NULL;
static volatile LONG   g_WorkerShutdown = 0;

static UINT8  g_Ticket[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

static BOOLEAN g_SessionActive = FALSE;
static UINT64  g_Nonce = 0;
static UINT64  g_Key0 = 0;
static UINT64  g_Key1 = 0;
static UINT64  g_SessionMagic = 0;
static volatile LONG64 g_Seq = 1;

// ── VMCALL execution with structured exception handling ─────────────────────

static UINT64 SafeRawVmcall(UINT64 magic, UINT64 id, UINT64 p1, UINT64 p2, UINT64 mac, UINT64 p3) {
    __try {
        return HvAsmVmcall(magic, id, p1, p2, mac, p3);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return (UINT64)-1;
    }
}

static BOOLEAN HvInitializeSession(const UINT8 *customTicket) {
    if (customTicket) {
        RtlCopyMemory(g_Ticket, customTicket, 32);
    }

    const UINT64 *ticketWords = (const UINT64 *)g_Ticket;
    UINT64 bootMagic = HvBootMagic(ticketWords);

    UINT64 nonce = SafeRawVmcall(bootMagic, 0 /* HV_HYPERCALL_DETECT */, 0, 0, 0, 0);
    if (nonce <= 0xFF || nonce == (UINT64)-1 || nonce == (UINT64)-2 || nonce == HV_STATUS_NOT_OURS) {
        g_SessionActive = FALSE;
        return FALSE;
    }

    g_Nonce = nonce;
    HvDeriveSession(ticketWords, g_Nonce, &g_Key0, &g_Key1);
    g_SessionMagic = HvSessionMagic(g_Key0, g_Key1);
    g_SessionActive = TRUE;
    InterlockedExchange64(&g_Seq, 1);

    KdPrint(("[HvDrv] Hypervisor session initialized! Nonce=0x%016llX, Magic=0x%016llX\n",
             g_Nonce, g_SessionMagic));
    return TRUE;
}

static UINT64 HvAuthVmcall(UINT64 id, UINT64 p1, UINT64 p2, UINT64 p3) {
    if (!g_SessionActive && !HvInitializeSession(NULL)) {
        return HV_STATUS_NOT_OURS;
    }

    LONG64 curSeq = InterlockedIncrement64(&g_Seq) - 1;
    UINT64 words[6] = { g_SessionMagic, id, p1, p2, 0, (UINT64)curSeq };
    UINT64 mac = HvMacTuple(g_Key0, g_Key1, words);
    return SafeRawVmcall(g_SessionMagic, id, p1, p2, mac, p3);
}

// ── Dispatch Routines ───────────────────────────────────────────────────────

NTSTATUS HvCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS HvDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR bytesReturned = 0;

    switch (ioctl) {
        case IOCTL_HV_DETECT: {
            if (outLen < sizeof(HV_IOCTL_DETECT)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PHV_IOCTL_DETECT det = (PHV_IOCTL_DETECT)buf;
            BOOLEAN customGiven = FALSE;
            if (inLen >= sizeof(det->Ticket)) {
                for (int i = 0; i < 32; i++) {
                    if (det->Ticket[i] != 0) { customGiven = TRUE; break; }
                }
            }

            BOOLEAN ok = HvInitializeSession(customGiven ? det->Ticket : NULL);
            det->Status = ok ? HV_STATUS_SUCCESS : HV_STATUS_NOT_OURS;
            det->Nonce = g_Nonce;

            // Enumerate CPUs via CPUID canary
            ULONG activeCanaries = 0;
            ULONG numProcs = KeQueryActiveProcessorCount(NULL);
            for (ULONG i = 0; i < numProcs && i < 64; i++) {
                KAFFINITY mask = (KAFFINITY)1 << i;
                KeSetSystemAffinityThread(mask);
                int regs[4] = {0};
                __cpuidex(regs, 0x13371337, 0);
                if (regs[0] == 0x564D5831) activeCanaries++;
            }
            KeRevertToUserAffinityThread();

            det->CanaryActive = activeCanaries;
            det->ActiveCpuCount = activeCanaries;
            bytesReturned = sizeof(HV_IOCTL_DETECT);
            break;
        }

        case IOCTL_HV_QUERY_STATUS: {
            if (outLen < sizeof(HV_IOCTL_STATUS)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PHV_IOCTL_STATUS st = (PHV_IOCTL_STATUS)buf;
            UINT64 word = HvAuthVmcall(6 /* QUERY_STATUS */, 0, 0, 0);
            st->RawStatusWord = word;
            st->VcpuCount = (UINT32)(word & HV_STATUS_CPU_MASK);
            st->Running = (word & HV_STATUS_RUNNING_BIT) ? 1 : 0;
            st->DarkReason = (UINT32)((word >> 32) & 0xFF);
            st->TscScale = (UINT32)((word >> 40) & 0xFF);
            st->Status = HV_STATUS_SUCCESS;
            bytesReturned = sizeof(HV_IOCTL_STATUS);
            break;
        }

        case IOCTL_HV_SELFTEST: {
            if (outLen < sizeof(UINT64)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            *(PUINT64)buf = HvAuthVmcall(8 /* SELFTEST */, 0, 0, 0);
            bytesReturned = sizeof(UINT64);
            break;
        }

        case IOCTL_HV_CAPABILITIES: {
            if (outLen < sizeof(HV_IOCTL_CAPABILITIES)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PHV_IOCTL_CAPABILITIES caps = (PHV_IOCTL_CAPABILITIES)buf;
            caps->SupportedBitmask = HvAuthVmcall(0x000B /* CAPABILITIES */, 0, 0, 0);
            caps->AbiVersion = 1;
            caps->Status = HV_STATUS_SUCCESS;
            bytesReturned = sizeof(HV_IOCTL_CAPABILITIES);
            break;
        }

        case IOCTL_HV_GET_CR3: {
            if (inLen < sizeof(HV_IOCTL_GET_CR3) || outLen < sizeof(HV_IOCTL_GET_CR3)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PHV_IOCTL_GET_CR3 cr = (PHV_IOCTL_GET_CR3)buf;
            cr->Cr3 = HvAuthVmcall(4 /* GET_CR3 */, (UINT64)cr->ProcessId, 0, 0);
            cr->Status = (cr->Cr3 != (UINT64)-1) ? HV_STATUS_SUCCESS : HV_STATUS_ACCESS_DENIED;
            bytesReturned = sizeof(HV_IOCTL_GET_CR3);
            break;
        }

        case IOCTL_HV_TRANSLATE: {
            if (inLen < sizeof(HV_IOCTL_TRANSLATE) || outLen < sizeof(HV_IOCTL_TRANSLATE)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PHV_IOCTL_TRANSLATE tr = (PHV_IOCTL_TRANSLATE)buf;
            UINT64 cr3 = tr->Cr3 ? tr->Cr3 : __readcr3();
            tr->PhysicalAddress = HvAuthVmcall(3 /* TRANSLATE */, cr3, tr->VirtualAddress, 0);
            tr->Status = (tr->PhysicalAddress != (UINT64)-1) ? HV_STATUS_SUCCESS : HV_STATUS_ACCESS_DENIED;
            bytesReturned = sizeof(HV_IOCTL_TRANSLATE);
            break;
        }

        case IOCTL_HV_READ_PHYS: {
            if (inLen < sizeof(HV_IOCTL_READ_PHYS) || outLen < sizeof(HV_IOCTL_READ_PHYS)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PHV_IOCTL_READ_PHYS rp = (PHV_IOCTL_READ_PHYS)buf;
            if (rp->Size == 0 || rp->Size > 4096) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            rp->Status = HvAuthVmcall(1 /* READ_PHYS */, rp->PhysicalAddress, (UINT64)(UINTN)rp->Buffer, rp->Size);
            bytesReturned = sizeof(HV_IOCTL_READ_PHYS);
            break;
        }

        case IOCTL_HV_WRITE_PHYS: {
            if (inLen < sizeof(HV_IOCTL_WRITE_PHYS) || outLen < sizeof(HV_IOCTL_WRITE_PHYS)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PHV_IOCTL_WRITE_PHYS wp = (PHV_IOCTL_WRITE_PHYS)buf;
            if (wp->Size == 0 || wp->Size > 4096) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            wp->Status = HvAuthVmcall(2 /* WRITE_PHYS */, wp->PhysicalAddress, (UINT64)(UINTN)wp->Buffer, wp->Size);
            bytesReturned = sizeof(HV_IOCTL_WRITE_PHYS);
            break;
        }

        case IOCTL_HV_READ_VIRT: {
            if (inLen < sizeof(HV_IOCTL_READ_VIRT) || outLen < sizeof(HV_IOCTL_READ_VIRT)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PHV_IOCTL_READ_VIRT rv = (PHV_IOCTL_READ_VIRT)buf;
            if (rv->Size == 0 || rv->Size > 4096) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            UINT64 pidAndSize = ((UINT64)rv->Size << 32) | rv->ProcessId;
            rv->Status = HvAuthVmcall(0x000E /* READ_VIRT */, pidAndSize, rv->VirtualAddress, (UINT64)(UINTN)rv->Buffer);
            bytesReturned = sizeof(HV_IOCTL_READ_VIRT);
            break;
        }

        case IOCTL_HV_WRITE_VIRT: {
            if (inLen < sizeof(HV_IOCTL_WRITE_VIRT) || outLen < sizeof(HV_IOCTL_WRITE_VIRT)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PHV_IOCTL_WRITE_VIRT wv = (PHV_IOCTL_WRITE_VIRT)buf;
            if (wv->Size == 0 || wv->Size > 4096) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            UINT64 pidAndSize = ((UINT64)wv->Size << 32) | wv->ProcessId;
            wv->Status = HvAuthVmcall(0x000F /* WRITE_VIRT */, pidAndSize, wv->VirtualAddress, (UINT64)(UINTN)wv->Buffer);
            bytesReturned = sizeof(HV_IOCTL_WRITE_VIRT);
            break;
        }

        case IOCTL_HV_GET_KERNEL_BASE: {
            if (outLen < sizeof(HV_IOCTL_KERNEL_BASE)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PHV_IOCTL_KERNEL_BASE kb = (PHV_IOCTL_KERNEL_BASE)buf;
            kb->KernelBase = HvAuthVmcall(0x0010 /* GET_KERNEL_BASE */, 0, 0, 0);
            kb->Status = (kb->KernelBase != 0) ? HV_STATUS_SUCCESS : HV_STATUS_ACCESS_DENIED;
            bytesReturned = sizeof(HV_IOCTL_KERNEL_BASE);
            break;
        }

        case IOCTL_HV_INVALIDATE_EPT: {
            UINT64 res = HvAuthVmcall(7 /* INVALIDATE_EPT */, 0, 0, 0);
            if (outLen >= sizeof(UINT64)) {
                *(PUINT64)buf = res;
                bytesReturned = sizeof(UINT64);
            }
            break;
        }

        case IOCTL_HV_INSTALL_HOOK: {
            if (inLen < sizeof(HV_IOCTL_HOOK) || outLen < sizeof(HV_IOCTL_HOOK)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PHV_IOCTL_HOOK hk = (PHV_IOCTL_HOOK)buf;
            if (hk->HookLength == 0 || hk->HookLength > 128) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            // Dispatches EPT hook to hypervisor
            hk->Status = HvAuthVmcall(0x0011 /* EPT_HOOK */, hk->TargetGpa, (UINT64)(UINTN)hk->HookCode, hk->HookLength);
            bytesReturned = sizeof(HV_IOCTL_HOOK);
            break;
        }

        case IOCTL_HV_REMOVE_HOOK: {
            if (inLen < sizeof(HV_IOCTL_HOOK) || outLen < sizeof(HV_IOCTL_HOOK)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PHV_IOCTL_HOOK hk = (PHV_IOCTL_HOOK)buf;
            hk->Status = HvAuthVmcall(0x0012 /* EPT_UNHOOK */, hk->TargetGpa, 0, 0);
            bytesReturned = sizeof(HV_IOCTL_HOOK);
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ── Shared-Memory / Manual-Mapped Request Handling (Inspired by Kratos) ──

static void HvHandleShmRequest(HV_SHM_REQUEST *req) {
    req->Status = HV_SHM_STATUS_FAIL;
    req->Result = 0;

    if (req->Magic != HV_SHM_MAGIC)
        return;

    switch (req->OpCode) {
    case HV_SHM_OP_PING:
        req->Result = HV_SHM_MAGIC;
        req->Status = HV_SHM_STATUS_OK;
        break;

    case HV_SHM_OP_GET_CR3: {
        UINT64 cr3 = HvAuthVmcall(0x0004 /* GET_CR3 */, req->Pid, 0, 0);
        req->Result = cr3;
        req->Status = (cr3 != 0 && cr3 != (UINT64)-1) ? HV_SHM_STATUS_OK : HV_SHM_STATUS_BAD_PID;
        break;
    }

    case HV_SHM_OP_TRANSLATE: {
        UINT64 pa = HvAuthVmcall(0x0003 /* TRANSLATE */, 0 /* cr3 */, req->Address, 0);
        req->Result = pa;
        req->Status = (pa != 0 && pa != (UINT64)-1) ? HV_SHM_STATUS_OK : HV_SHM_STATUS_BAD_ADDR;
        break;
    }

    case HV_SHM_OP_READ_VIRT: {
        if (req->Size == 0 || req->Size > HV_SHM_DATA_SIZE) {
            req->Status = HV_SHM_STATUS_BAD_SIZE;
            break;
        }
        UINT64 pAndS = ((UINT64)req->Size << 32) | (UINT64)req->Pid;
        UINT64 st = HvAuthVmcall(0x000E /* READ_VIRT */, pAndS, req->Address, (UINT64)(UINTN)req->Data);
        req->Result = st;
        req->Status = (st == 0) ? HV_SHM_STATUS_OK : HV_SHM_STATUS_FAIL;
        break;
    }

    case HV_SHM_OP_WRITE_VIRT: {
        if (req->Size == 0 || req->Size > HV_SHM_DATA_SIZE) {
            req->Status = HV_SHM_STATUS_BAD_SIZE;
            break;
        }
        UINT64 pAndS = ((UINT64)req->Size << 32) | (UINT64)req->Pid;
        UINT64 st = HvAuthVmcall(0x000F /* WRITE_VIRT */, pAndS, req->Address, (UINT64)(UINTN)req->Data);
        req->Result = st;
        req->Status = (st == 0) ? HV_SHM_STATUS_OK : HV_SHM_STATUS_FAIL;
        break;
    }

    case HV_SHM_OP_READ_PHYS: {
        if (req->Size == 0 || req->Size > HV_SHM_DATA_SIZE) {
            req->Status = HV_SHM_STATUS_BAD_SIZE;
            break;
        }
        UINT64 st = HvAuthVmcall(0x0001 /* READ_PHYS */, req->Address, (UINT64)(UINTN)req->Data, req->Size);
        req->Result = st;
        req->Status = (st == 0) ? HV_SHM_STATUS_OK : HV_SHM_STATUS_FAIL;
        break;
    }

    case HV_SHM_OP_WRITE_PHYS: {
        if (req->Size == 0 || req->Size > HV_SHM_DATA_SIZE) {
            req->Status = HV_SHM_STATUS_BAD_SIZE;
            break;
        }
        UINT64 st = HvAuthVmcall(0x0002 /* WRITE_PHYS */, req->Address, (UINT64)(UINTN)req->Data, req->Size);
        req->Result = st;
        req->Status = (st == 0) ? HV_SHM_STATUS_OK : HV_SHM_STATUS_FAIL;
        break;
    }

    case HV_SHM_OP_GET_KERNEL_BASE: {
        req->Result = HvAuthVmcall(0x0010 /* GET_KERNEL_BASE */, 0, 0, 0);
        req->Status = (req->Result != 0) ? HV_SHM_STATUS_OK : HV_SHM_STATUS_FAIL;
        break;
    }

    case HV_SHM_OP_STATUS: {
        req->Result = HvAuthVmcall(0x0006 /* QUERY_STATUS */, 0, 0, 0);
        req->Status = HV_SHM_STATUS_OK;
        break;
    }

    case HV_SHM_OP_CAPABILITIES: {
        req->Result = HvAuthVmcall(0x000B /* CAPABILITIES */, 0, 0, 0);
        req->Status = HV_SHM_STATUS_OK;
        break;
    }

    default:
        req->Status = HV_SHM_STATUS_FAIL;
        break;
    }
}

static VOID HvWorkerThread(PVOID context) {
    UNREFERENCED_PARAMETER(context);
    HV_SHM_REQUEST *req = g_CommBuf;
    LARGE_INTEGER interval;
    interval.QuadPart = -20000; // 2 ms poll

    KdPrint(("[HvDrv] Stealth worker thread active.\n"));

    while (!g_WorkerShutdown) {
        if (InterlockedCompareExchange(&req->Lock,
                HV_SHM_STATE_REQUEST, HV_SHM_STATE_REQUEST) == HV_SHM_STATE_REQUEST) {
            HvHandleShmRequest(req);
            _ReadWriteBarrier();
            InterlockedExchange(&req->Lock, HV_SHM_STATE_DONE);
        } else {
            KeDelayExecutionThread(KernelMode, FALSE, &interval);
        }
    }

    KdPrint(("[HvDrv] Stealth worker thread exiting.\n"));
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ── Unload & DriverEntry ────────────────────────────────────────────────────

VOID HvDriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    KdPrint(("[HvDrv] Driver unloading...\n"));

    if (g_ThreadHandle) {
        g_WorkerShutdown = 1;
    }

    IoDeleteSymbolicLink(&g_SymLinkName);
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    if (g_CommBuf) {
        ExFreePoolWithTag(g_CommBuf, 'vEdH');
        g_CommBuf = NULL;
    }

    KdPrint(("[HvDrv] Driver unloaded cleanly.\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    KdPrint(("[HvDrv] DriverEntry loading (DriverObject=%p)...\n", DriverObject));

    // Attempt early hypervisor discovery
    if (HvInitializeSession(NULL)) {
        KdPrint(("[HvDrv] Successfully paired with resident HvEfi hypervisor!\n"));
    } else {
        KdPrint(("[HvDrv] HvEfi hypervisor not yet detected; will retry on first request.\n"));
    }

    // ── Mode 1: Standard WDM Service Mode ───────────────────────────────────
    if (DriverObject != NULL) {
        RtlInitUnicodeString(&g_DeviceName, HV_DEVICE_NAME_W);
        RtlInitUnicodeString(&g_SymLinkName, HV_DOS_DEVICE_NAME_W);

        NTSTATUS status = IoCreateDevice(
            DriverObject,
            0,
            &g_DeviceName,
            HV_DEVICE_TYPE,
            FILE_DEVICE_SECURE_OPEN,
            FALSE,
            &g_DeviceObject
        );

        if (!NT_SUCCESS(status)) {
            KdPrint(("[HvDrv] Failed to create device object: 0x%08X\n", status));
            return status;
        }

        status = IoCreateSymbolicLink(&g_SymLinkName, &g_DeviceName);
        if (!NT_SUCCESS(status)) {
            KdPrint(("[HvDrv] Failed to create symbolic link: 0x%08X\n", status));
            IoDeleteDevice(g_DeviceObject);
            g_DeviceObject = NULL;
            return status;
        }

        DriverObject->MajorFunction[IRP_MJ_CREATE] = HvCreateClose;
        DriverObject->MajorFunction[IRP_MJ_CLOSE]  = HvCreateClose;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HvDeviceControl;
        DriverObject->DriverUnload = HvDriverUnload;

        g_DeviceObject->Flags |= DO_BUFFERED_IO;
        g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
        KdPrint(("[HvDrv] Standard WDM device initialized successfully.\n"));
    }

    // ── Mode 2: Stealth Shared-Memory / Manual-Mapped Mode (Kratos-Compatible) ─
    // Always initialize the shared-memory comm buffer & beacon at PA 0x1000 so
    // either mapped drivers or usermode callers without device handles can communicate.
    g_CommBuf = (HV_SHM_REQUEST *)ExAllocatePool2(POOL_FLAG_NON_PAGED, HV_SHM_SIZE, 'vEdH');
    if (g_CommBuf) {
        RtlZeroMemory(g_CommBuf, HV_SHM_SIZE);
        PHYSICAL_ADDRESS commPa = MmGetPhysicalAddress(g_CommBuf);
        g_CommPA = (UINT64)commPa.QuadPart;

        HV_BEACON beacon;
        beacon.Magic = HV_BEACON_MAGIC;
        beacon.CommVA = (UINT64)g_CommBuf;
        beacon.CommPA = g_CommPA;
        beacon.Magic2 = HV_BEACON_MAGIC2;

        // Publish beacon at PA 0x1000 via hypervisor physical write
        HvAuthVmcall(0x0002 /* WRITE_PHYS */, HV_BEACON_PA, (UINT64)(UINTN)&beacon, sizeof(beacon));

        NTSTATUS threadStatus = PsCreateSystemThread(
            &g_ThreadHandle,
            THREAD_ALL_ACCESS,
            NULL,
            NULL,
            NULL,
            HvWorkerThread,
            NULL
        );
        if (NT_SUCCESS(threadStatus)) {
            KdPrint(("[HvDrv] Shared-memory beacon published at PA 0x%llX (CommVA=0x%llX, CommPA=0x%llX)\n",
                     HV_BEACON_PA, (UINT64)g_CommBuf, g_CommPA));
        }
    }

    KdPrint(("[HvDrv] DriverEntry completed successfully.\n"));
    return STATUS_SUCCESS;
}
