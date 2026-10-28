// shared/hv_ioctl.h — IOCTL interface contract between HvDrv and user-mode applications.
//
// This header is dependency-free and consumable by both kernel drivers (WDM/KMDF)
// and user-mode Windows applications.

#ifndef HV_IOCTL_H
#define HV_IOCTL_H

#ifndef CTL_CODE
#pragma warning(push)
#pragma warning(disable: 4005)
#define CTL_CODE( DeviceType, Function, Method, Access ) ( \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)
#define METHOD_BUFFERED                 0
#define FILE_ANY_ACCESS                 0
#define FILE_READ_ACCESS          ( 0x0001 )    // file & pipe
#define FILE_WRITE_ACCESS         ( 0x0002 )    // file & pipe
#pragma warning(pop)
#endif

#define HV_DEVICE_TYPE                  0x8337

#define HV_DEVICE_NAME_W                L"\\Device\\HvDrv"
#define HV_DOS_DEVICE_NAME_W            L"\\DosDevices\\HvDrv"
#define HV_USER_DEVICE_NAME             "\\\\.\\HvDrv"

// ── IOCTL Definitions ───────────────────────────────────────────────────────

#define IOCTL_HV_DETECT \
    CTL_CODE(HV_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_HV_QUERY_STATUS \
    CTL_CODE(HV_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_HV_SELFTEST \
    CTL_CODE(HV_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_HV_CAPABILITIES \
    CTL_CODE(HV_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_HV_GET_CR3 \
    CTL_CODE(HV_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_HV_TRANSLATE \
    CTL_CODE(HV_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_HV_READ_PHYS \
    CTL_CODE(HV_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HV_WRITE_PHYS \
    CTL_CODE(HV_DEVICE_TYPE, 0x807, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HV_READ_VIRT \
    CTL_CODE(HV_DEVICE_TYPE, 0x808, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HV_WRITE_VIRT \
    CTL_CODE(HV_DEVICE_TYPE, 0x809, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HV_GET_KERNEL_BASE \
    CTL_CODE(HV_DEVICE_TYPE, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_HV_INVALIDATE_EPT \
    CTL_CODE(HV_DEVICE_TYPE, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_HV_INSTALL_HOOK \
    CTL_CODE(HV_DEVICE_TYPE, 0x80C, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HV_REMOVE_HOOK \
    CTL_CODE(HV_DEVICE_TYPE, 0x80D, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

// ── IOCTL Request / Response Payloads ───────────────────────────────────────

#pragma pack(push, 8)

typedef struct _HV_IOCTL_DETECT {
    UINT8   Ticket[32];         // In (optional; 0 uses default/loaded ticket)
    UINT64  Nonce;              // Out: Hypervisor session nonce
    UINT32  ActiveCpuCount;     // Out: Active virtualized CPUs
    UINT32  CanaryActive;       // Out: Canary CPUID response count
    UINT64  Status;             // Out: Return status
} HV_IOCTL_DETECT, *PHV_IOCTL_DETECT;

typedef struct _HV_IOCTL_STATUS {
    UINT64  RawStatusWord;      // Out: Hypercall 6 raw status
    UINT32  VcpuCount;          // Out: Number of logical vCPUs
    UINT32  Running;            // Out: Hypervisor active (1) or inactive (0)
    UINT32  DarkReason;         // Out: Diagnostic dark reason code
    UINT32  TscScale;           // Out: TSC frequency ratio
    UINT64  Status;             // Out: Return status
} HV_IOCTL_STATUS, *PHV_IOCTL_STATUS;

typedef struct _HV_IOCTL_CAPABILITIES {
    UINT64  SupportedBitmask;   // Out: Supported opcode bitmask
    UINT32  AbiVersion;         // Out: Interface ABI revision
    UINT64  Status;             // Out: Return status
} HV_IOCTL_CAPABILITIES, *PHV_IOCTL_CAPABILITIES;

typedef struct _HV_IOCTL_TRANSLATE {
    UINT64  Cr3;                // In: Process CR3 (0 for current/caller)
    UINT64  VirtualAddress;     // In: Target virtual address
    UINT64  PhysicalAddress;    // Out: Translated host physical address
    UINT64  Status;             // Out: Return status
} HV_IOCTL_TRANSLATE, *PHV_IOCTL_TRANSLATE;

typedef struct _HV_IOCTL_GET_CR3 {
    UINT32  ProcessId;          // In: Target PID (0 for System process)
    UINT64  Cr3;                // Out: Process DirectoryTableBase
    UINT64  Status;             // Out: Return status
} HV_IOCTL_GET_CR3, *PHV_IOCTL_GET_CR3;

typedef struct _HV_IOCTL_READ_PHYS {
    UINT64  PhysicalAddress;    // In: Source PA
    UINT32  Size;               // In: Bytes to read (max 4096)
    UINT8   Buffer[4096];       // Out: Data read
    UINT64  Status;             // Out: Return status
} HV_IOCTL_READ_PHYS, *PHV_IOCTL_READ_PHYS;

typedef struct _HV_IOCTL_WRITE_PHYS {
    UINT64  PhysicalAddress;    // In: Destination PA
    UINT32  Size;               // In: Bytes to write (max 4096)
    UINT8   Buffer[4096];       // In: Data to write
    UINT64  Status;             // Out: Return status
} HV_IOCTL_WRITE_PHYS, *PHV_IOCTL_WRITE_PHYS;

typedef struct _HV_IOCTL_READ_VIRT {
    UINT32  ProcessId;          // In: Target PID (0 for current process)
    UINT64  VirtualAddress;     // In: Target virtual address
    UINT32  Size;               // In: Bytes to read (max 4096)
    UINT8   Buffer[4096];       // Out: Data read
    UINT64  Status;             // Out: Return status
} HV_IOCTL_READ_VIRT, *PHV_IOCTL_READ_VIRT;

typedef struct _HV_IOCTL_WRITE_VIRT {
    UINT32  ProcessId;          // In: Target PID (0 for current process)
    UINT64  VirtualAddress;     // In: Target virtual address
    UINT32  Size;               // In: Bytes to write (max 4096)
    UINT8   Buffer[4096];       // In: Data to write
    UINT64  Status;             // Out: Return status
} HV_IOCTL_WRITE_VIRT, *PHV_IOCTL_WRITE_VIRT;

typedef struct _HV_IOCTL_KERNEL_BASE {
    UINT64  KernelBase;         // Out: ntoskrnl.exe image base VA
    UINT64  Status;             // Out: Return status
} HV_IOCTL_KERNEL_BASE, *PHV_IOCTL_KERNEL_BASE;

typedef struct _HV_IOCTL_HOOK {
    UINT64  TargetGpa;          // In: GPA of target code page
    UINT32  HookOffset;         // In: Offset within page (0..4095)
    UINT32  HookLength;         // In: Length of hook bytes (max 128)
    UINT8   HookCode[128];      // In: Replacement hook bytes
    UINT8   OriginalBytes[128]; // Out: Preserved original bytes
    UINT64  Status;             // Out: Return status
} HV_IOCTL_HOOK, *PHV_IOCTL_HOOK;

// ── Shared Memory Beacon & Request Protocol (Manual-Mapped / Stealth Mode) ──

#define HV_BEACON_PA                    0x1000ULL
#define HV_BEACON_MAGIC                 0x4856505445434F4DULL  // "HVPTECOM"
#define HV_BEACON_MAGIC2                (~HV_BEACON_MAGIC)

#define HV_SHM_MAGIC                    0x50544531ULL          // 'PTE1'
#define HV_SHM_SIZE                     (8 * 4096)
#define HV_SHM_DATA_SIZE                4096

// Shared memory handshake states
#define HV_SHM_STATE_IDLE               0
#define HV_SHM_STATE_REQUEST            1
#define HV_SHM_STATE_DONE               2
#define HV_SHM_STATE_SHUTDOWN           0xFF

// Shared memory operation codes
#define HV_SHM_OP_PING                  0x00
#define HV_SHM_OP_READ_VIRT             0x01
#define HV_SHM_OP_WRITE_VIRT            0x02
#define HV_SHM_OP_GET_CR3               0x03
#define HV_SHM_OP_TRANSLATE             0x04
#define HV_SHM_OP_READ_PHYS             0x05
#define HV_SHM_OP_WRITE_PHYS            0x06
#define HV_SHM_OP_GET_KERNEL_BASE       0x07
#define HV_SHM_OP_STATUS                0x08
#define HV_SHM_OP_CAPABILITIES          0x09

// Status codes
#define HV_SHM_STATUS_OK                0
#define HV_SHM_STATUS_FAIL              1
#define HV_SHM_STATUS_BAD_PID           2
#define HV_SHM_STATUS_BAD_ADDR          3
#define HV_SHM_STATUS_BAD_SIZE          4

typedef struct _HV_BEACON {
    UINT64 Magic;
    UINT64 CommVA;
    UINT64 CommPA;
    UINT64 Magic2;
} HV_BEACON, *PHV_BEACON;

typedef struct _HV_SHM_REQUEST {
    volatile LONG  Lock;         // HV_SHM_STATE_*
    UINT32         OpCode;       // HV_SHM_OP_*
    UINT32         Status;       // HV_SHM_STATUS_*
    UINT32         Pid;          // Target PID
    UINT64         Address;      // Virtual or physical address
    UINT64         Size;         // Bytes to read/write
    UINT64         Result;       // Returned value (CR3, PA, etc.)
    UINT64         Magic;        // HV_SHM_MAGIC
    UINT8          Data[HV_SHM_DATA_SIZE];
} HV_SHM_REQUEST, *PHV_SHM_REQUEST;

#pragma pack(pop)

#endif // HV_IOCTL_H
