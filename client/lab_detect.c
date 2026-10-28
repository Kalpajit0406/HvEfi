#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <intrin.h>

#if defined(__has_include)
#if __has_include("../shared/hv_siphash.h")
#include "../shared/hv_siphash.h"
#include "../shared/hv_status.h"
#include "../shared/hv_ioctl.h"
#elif __has_include("shared/hv_siphash.h")
#include "shared/hv_siphash.h"
#include "shared/hv_status.h"
#endif
#else
#include "../shared/hv_siphash.h"
#include "../shared/hv_status.h"
#endif

// Hypercall IDs matching hypervisor/hvdefs.h
#define HV_HYPERCALL_DETECT             0x0000
#define HV_HYPERCALL_READ_PHYS          0x0001
#define HV_HYPERCALL_WRITE_PHYS         0x0002
#define HV_HYPERCALL_TRANSLATE          0x0003
#define HV_HYPERCALL_GET_CR3            0x0004
#define HV_HYPERCALL_UNLOAD             0x0005
#define HV_HYPERCALL_QUERY_STATUS       0x0006
#define HV_HYPERCALL_INVALIDATE_EPT     0x0007
#define HV_HYPERCALL_SELFTEST           0x0008
#define HV_HYPERCALL_SET_CR3_OFFSET     0x000A
#define HV_HYPERCALL_CAPABILITIES       0x000B
#define HV_HYPERCALL_QUERY_EXIT_COUNTS  0x000C
#define HV_HYPERCALL_READ_VIRT          0x000E
#define HV_HYPERCALL_WRITE_VIRT         0x000F
#define HV_HYPERCALL_GET_KERNEL_BASE    0x0010
#define HV_HYPERCALL_EPT_HOOK           0x0011
#define HV_HYPERCALL_EPT_UNHOOK         0x0012

// Default lab ticket (32 bytes)
static uint8_t s_Ticket[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

static uint8_t *s_VmcallStub = NULL;
typedef uint64_t (*VmcallFn_t)(uint64_t magic, uint64_t id,
                               uint64_t p1, uint64_t p2,
                               uint64_t mac, uint64_t p3);

static BOOL BuildVmcallStub(void) {
    if (s_VmcallStub) return true;
    static const uint8_t stub[] = {
        0x4C, 0x8B, 0x54, 0x24, 0x28,  // mov r10, [rsp+28h]
        0x4C, 0x8B, 0x5C, 0x24, 0x30,  // mov r11, [rsp+30h]
        0x0F, 0x01, 0xC1,              // vmcall
        0xC3                           // ret
    };
    s_VmcallStub = (uint8_t *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!s_VmcallStub) return false;
    memcpy(s_VmcallStub, stub, sizeof(stub));
    DWORD old;
    VirtualProtect(s_VmcallStub, 4096, PAGE_EXECUTE_READ, &old);
    FlushInstructionCache(GetCurrentProcess(), s_VmcallStub, 4096);
    return true;
}

static uint64_t RawVmcall(uint64_t magic, uint64_t id,
                          uint64_t p1, uint64_t p2,
                          uint64_t mac, uint64_t p3) {
    if (!s_VmcallStub && !BuildVmcallStub()) return (uint64_t)-1;
    VmcallFn_t fn = (VmcallFn_t)s_VmcallStub;
    __try {
        return fn(magic, id, p1, p2, mac, p3);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return (uint64_t)-1;
    }
}

static bool TryLoadTicketFile(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    uint8_t buf[32];
    size_t readBytes = fread(buf, 1, 32, f);
    fclose(f);
    if (readBytes == 32) {
        memcpy(s_Ticket, buf, 32);
        return true;
    }
    return false;
}

static void AutoDiscoverTicket(void) {
    const char *candidates[] = {
        "hvticket",
        "..\\hvticket",
        "F:\\HvEfi\\hvticket",
        "D:\\EFI\\Boot\\hvticket",
        "C:\\EFI\\Boot\\hvticket"
    };
    for (size_t i = 0; i < sizeof(candidates)/sizeof(candidates[0]); i++) {
        if (TryLoadTicketFile(candidates[i])) {
            printf("[*] Loaded ticket from: %s\n", candidates[i]);
            return;
        }
    }
}

static void HexDump(const void *data, size_t size, uint64_t baseAddr) {
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < size; i += 16) {
        printf("    0x%016llX: ", baseAddr + i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) printf("%02X ", p[i + j]);
            else printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) {
                uint8_t c = p[i + j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
        }
        printf("|\n");
    }
}

static void PrintHelp(const char *prog) {
    printf("HvEfi Comprehensive Windows Runtime Verification Client\n");
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("  --all                  Run complete diagnostic test suite across all hypercalls (default)\n");
    printf("  --detect               Quick residency check (Canary CPUID & VMCALL detect only)\n");
    printf("  --status               Query hypervisor status word, running flag, and active vCPUs\n");
    printf("  --capabilities         Query hypervisor supported opcode bitmask and ABI version\n");
    printf("  --bench [iterations]   Benchmark VMCALL execution latency (CPU cycle delta)\n");
    printf("  --read-phys <pa> <len> Read physical memory directly through hypervisor\n");
    printf("  --read-virt <pid> <va> <len> Read target process virtual memory via hypervisor\n");
    printf("  --kernel-base          Query ntoskrnl base address discovered by hypervisor\n");
    printf("  --invept               Trigger hypervisor global EPT TLB invalidation\n");
    printf("  --ticket <file>        Specify custom 32-byte ticket file\n");
    printf("  --json                 Output test results in JSON format\n");
    printf("  --help                 Display this help message\n");
}

static bool RunDriverTests(bool optJson, uint64_t targetPa, uint32_t targetPid, uint64_t targetVa, uint32_t readLen) {
    HANDLE hDev = CreateFileA(HV_USER_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDev == INVALID_HANDLE_VALUE) {
        if (!optJson) printf("[-] Failed to open device %s (Error=%lu). Ensure HvDrv service is started.\n",
                             HV_USER_DEVICE_NAME, GetLastError());
        return false;
    }

    if (!optJson) printf("[+] Successfully opened handle to %s\n", HV_USER_DEVICE_NAME);

    // 1. IOCTL_HV_DETECT
    HV_IOCTL_DETECT det = {0};
    DWORD bytes = 0;
    if (DeviceIoControl(hDev, IOCTL_HV_DETECT, &det, sizeof(det), &det, sizeof(det), &bytes, NULL)) {
        if (!optJson) printf("[+] IOCTL_HV_DETECT: Nonce=0x%016llX, Status=0x%llX\n", det.Nonce, det.Status);
    }

    // 2. IOCTL_HV_QUERY_STATUS
    HV_IOCTL_STATUS st = {0};
    if (DeviceIoControl(hDev, IOCTL_HV_QUERY_STATUS, &st, sizeof(st), &st, sizeof(st), &bytes, NULL)) {
        if (!optJson) printf("[+] IOCTL_HV_QUERY_STATUS: VcpuCount=%u, Running=%u, RawStatusWord=0x%016llX\n",
                             st.VcpuCount, st.Running, st.RawStatusWord);
    }

    // 3. IOCTL_HV_SELFTEST
    UINT64 selftestStatus = (UINT64)-1;
    if (DeviceIoControl(hDev, IOCTL_HV_SELFTEST, NULL, 0, &selftestStatus, sizeof(selftestStatus), &bytes, NULL)) {
        if (!optJson) printf("[+] IOCTL_HV_SELFTEST: Status=0x%llX (%s)\n",
                             selftestStatus, selftestStatus == 0 ? "PASSED" : "FAILED");
    }

    // 4. IOCTL_HV_CAPABILITIES
    HV_IOCTL_CAPABILITIES caps = {0};
    if (DeviceIoControl(hDev, IOCTL_HV_CAPABILITIES, &caps, sizeof(caps), &caps, sizeof(caps), &bytes, NULL)) {
        if (!optJson) printf("[+] IOCTL_HV_CAPABILITIES: AbiVersion=%u, SupportedBitmask=0x%016llX\n",
                             caps.AbiVersion, caps.SupportedBitmask);
    }

    // 5. IOCTL_HV_GET_KERNEL_BASE
    HV_IOCTL_KERNEL_BASE kb = {0};
    if (DeviceIoControl(hDev, IOCTL_HV_GET_KERNEL_BASE, &kb, sizeof(kb), &kb, sizeof(kb), &bytes, NULL)) {
        if (!optJson) printf("[+] IOCTL_HV_GET_KERNEL_BASE: ntoskrnl VA=0x%016llX, Status=0x%llX\n",
                             kb.KernelBase, kb.Status);
    }

    // 6. Optional Physical Read
    if (targetPa != 0) {
        HV_IOCTL_READ_PHYS rp = {0};
        rp.PhysicalAddress = targetPa;
        rp.Size = (readLen > 4096) ? 4096 : readLen;
        if (DeviceIoControl(hDev, IOCTL_HV_READ_PHYS, &rp, sizeof(rp), &rp, sizeof(rp), &bytes, NULL)) {
            if (!optJson) {
                printf("[+] IOCTL_HV_READ_PHYS: PA=0x%016llX, Size=%u, Status=0x%llX\n",
                       rp.PhysicalAddress, rp.Size, rp.Status);
                HexDump(rp.Buffer, rp.Size, rp.PhysicalAddress);
            }
        }
    }

    CloseHandle(hDev);
    return true;
}

static uint64_t AuthVmcall(uint64_t sessionMagic, uint64_t key0, uint64_t key1,
                           uint64_t *pSeq, uint64_t id,
                           uint64_t p1, uint64_t p2, uint64_t p3) {
    uint64_t words[6] = { sessionMagic, id, p1, p2, 0, *pSeq };
    uint64_t mac = HvMacTuple(key0, key1, words);
    uint64_t ret = RawVmcall(sessionMagic, id, p1, p2, mac, p3);
    (*pSeq)++;
    return ret;
}

int main(int argc, char **argv) {
    bool optAll = true;
    bool optDetectOnly = false;
    bool optStatusOnly = false;
    bool optCapsOnly = false;
    bool optBench = false;
    bool optReadPhys = false;
    bool optReadVirt = false;
    bool optKernelBase = false;
    bool optInvept = false;
    bool optJson = false;
    bool optDriver = false;

    uint32_t benchIterations = 1000;
    uint64_t targetPa = 0;
    uint32_t targetPid = 0;
    uint64_t targetVa = 0;
    uint32_t readLen = 64;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintHelp(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--detect") == 0) {
            optDetectOnly = true; optAll = false;
        } else if (strcmp(argv[i], "--status") == 0) {
            optStatusOnly = true; optAll = false;
        } else if (strcmp(argv[i], "--capabilities") == 0) {
            optCapsOnly = true; optAll = false;
        } else if (strcmp(argv[i], "--bench") == 0) {
            optBench = true; optAll = false;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                benchIterations = (uint32_t)strtoul(argv[++i], NULL, 10);
                if (benchIterations == 0) benchIterations = 1000;
            }
        } else if (strcmp(argv[i], "--read-phys") == 0) {
            optReadPhys = true; optAll = false;
            if (i + 1 < argc) targetPa = strtoull(argv[++i], NULL, 0);
            if (i + 1 < argc && argv[i + 1][0] != '-') readLen = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--read-virt") == 0) {
            optReadVirt = true; optAll = false;
            if (i + 1 < argc) targetPid = (uint32_t)strtoul(argv[++i], NULL, 0);
            if (i + 1 < argc) targetVa = strtoull(argv[++i], NULL, 0);
            if (i + 1 < argc && argv[i + 1][0] != '-') readLen = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--kernel-base") == 0) {
            optKernelBase = true; optAll = false;
        } else if (strcmp(argv[i], "--invept") == 0) {
            optInvept = true; optAll = false;
        } else if (strcmp(argv[i], "--ticket") == 0) {
            if (i + 1 < argc) {
                const char *tpath = argv[++i];
                if (!TryLoadTicketFile(tpath)) {
                    fprintf(stderr, "[-] Failed to read ticket file: %s\n", tpath);
                    return 1;
                }
            }
        } else if (strcmp(argv[i], "--driver") == 0) {
            optDriver = true;
        } else if (strcmp(argv[i], "--json") == 0) {
            optJson = true;
        }
    }

    if (optDriver) {
        if (!optJson) {
            printf("=================================================================\n");
            printf("[*] HvEfi Companion Driver Verification (IOCTL Bridge Mode)\n");
            printf("=================================================================\n");
        }
        bool ok = RunDriverTests(optJson, targetPa, targetPid, targetVa, readLen);
        return ok ? 0 : 1;
    }

    AutoDiscoverTicket();

    FILE *logF = fopen("hv_detect.log", "a");
    #define LOG(...) do { if (!optJson) printf(__VA_ARGS__); if (logF) { fprintf(logF, __VA_ARGS__); fflush(logF); } } while(0)

    if (!optJson) {
        LOG("=================================================================\n");
        LOG("[*] HvEfi Hypervisor Runtime Verification Suite (Full Scale)\n");
        LOG("=================================================================\n");
    }

    const uint64_t *ticketWords = (const uint64_t *)s_Ticket;
    uint64_t bootMagic = HvBootMagic(ticketWords);
    if (!optJson) {
        LOG("[+] Loaded Ticket: ");
        for (int i = 0; i < 32; i++) LOG("%02X", s_Ticket[i]);
        LOG("\n[+] Derived BootMagic: 0x%016llX\n", bootMagic);
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (!optJson) LOG("[*] System Processor Count: %u\n", si.dwNumberOfProcessors);

    // ── Canary CPUID Check ──────────────────────────────────────────────────
    DWORD activeCanary = 0;
    for (DWORD i = 0; i < si.dwNumberOfProcessors && i < 64; i++) {
        SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)1 << i);
        Sleep(1);
        int regs[4] = {0};
        __cpuidex(regs, 0x13371337, 0);
        if (regs[0] == 0x564D5831) { // 'VMX1'
            activeCanary++;
        }
    }
    SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)-1);
    if (!optJson) LOG("[*] Canary CPUID Leaf (0x13371337): %u / %u CPUs Active\n", activeCanary, si.dwNumberOfProcessors);

    // ── VMCALL DETECT across all CPUs ───────────────────────────────────────
    uint64_t detectedNonce = 0;
    DWORD activeVmcall = 0;
    for (DWORD i = 0; i < si.dwNumberOfProcessors && i < 64; i++) {
        SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)1 << i);
        Sleep(1);
        uint64_t res = RawVmcall(bootMagic, HV_HYPERCALL_DETECT, 0, 0, 0, 0);
        if (res != (uint64_t)-1 && res != (uint64_t)-2 && res != HV_STATUS_NOT_OURS && res > 0xFF) {
            activeVmcall++;
            detectedNonce = res;
        }
    }
    SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)-1);

    if (activeVmcall == 0) {
        if (optJson) {
            printf("{\"status\": \"error\", \"message\": \"Hypervisor not detected\", \"active_cpus\": 0}\n");
        } else {
            LOG("[-] Hypervisor was NOT detected via VMCALL (Bare metal or unauthenticated).\n");
        }
        if (logF) fclose(logF);
        return 1;
    }

    if (!optJson) LOG("[+] VMCALL DETECT Succeeded on %u CPUs! Nonce = 0x%016llX\n", activeVmcall, detectedNonce);

    if (optDetectOnly) {
        if (optJson) printf("{\"status\": \"ok\", \"active_cpus\": %u, \"nonce\": \"0x%016llX\"}\n", activeVmcall, detectedNonce);
        if (logF) fclose(logF);
        return 0;
    }

    // ── Derive Cryptographic Session Keys ───────────────────────────────────
    uint64_t key0 = 0, key1 = 0;
    HvDeriveSession(ticketWords, detectedNonce, &key0, &key1);
    uint64_t sessionMagic = HvSessionMagic(key0, key1);
    if (!optJson) LOG("[+] Session Keys Derived. SessionMagic = 0x%016llX\n", sessionMagic);

    uint64_t seq = 1;

    #define AUTH_VMCALL(id, p1, p2, p3) AuthVmcall(sessionMagic, key0, key1, &seq, (id), (p1), (p2), (p3))

    // ── Test 1: QUERY_STATUS ────────────────────────────────────────────────
    uint64_t statusWord = AUTH_VMCALL(HV_HYPERCALL_QUERY_STATUS, 0, 0, 0);
    uint32_t hvVcpus = (uint32_t)(statusWord & HV_STATUS_CPU_MASK);
    bool hvRunning = (statusWord & HV_STATUS_RUNNING_BIT) != 0;
    uint32_t darkReason = (uint32_t)((statusWord >> 32) & 0xFF);
    if (!optJson) {
        LOG("[+] [0x0006] QUERY_STATUS: 0x%016llX (vCPUs: %u, Running: %s, DarkReason: %u)\n",
            statusWord, hvVcpus, hvRunning ? "YES" : "NO", darkReason);
    }
    if (optStatusOnly) {
        if (optJson) printf("{\"status_word\": \"0x%016llX\", \"vcpus\": %u, \"running\": %s}\n", statusWord, hvVcpus, hvRunning ? "true" : "false");
        if (logF) fclose(logF);
        return 0;
    }

    // ── Test 2: SELFTEST ────────────────────────────────────────────────────
    uint64_t selftestRes = AUTH_VMCALL(HV_HYPERCALL_SELFTEST, 0, 0, 0);
    if (!optJson) {
        LOG("[+] [0x0008] SELFTEST: %s (Status: 0x%llX)\n",
            (selftestRes == HV_STATUS_SUCCESS) ? "PASSED" : "FAILED", selftestRes);
    }

    // ── Test 3: CAPABILITIES ────────────────────────────────────────────────
    uint64_t caps = AUTH_VMCALL(HV_HYPERCALL_CAPABILITIES, 0, 0, 0);
    if (!optJson) {
        LOG("[+] [0x000B] CAPABILITIES Bitmask: 0x%016llX\n", caps);
        LOG("    Supported Hypercalls:\n");
        const char *capNames[] = {
            "DETECT", "READ_PHYS", "WRITE_PHYS", "TRANSLATE", "GET_CR3", "UNLOAD",
            "QUERY_STATUS", "INVALIDATE_EPT", "SELFTEST", "SET_CR3_OFFSET", "READ_SCATTER",
            "CAPABILITIES", "QUERY_EXIT_COUNTS", "READ_VIRT", "WRITE_VIRT", "GET_KERNEL_BASE",
            "EPT_HOOK", "EPT_UNHOOK"
        };
        for (uint32_t b = 0; b < sizeof(capNames)/sizeof(capNames[0]); b++) {
            if (caps & (1ULL << b)) LOG("     - [0x%02X] %s\n", b, capNames[b]);
        }
    }
    if (optCapsOnly) {
        if (optJson) printf("{\"capabilities\": \"0x%016llX\"}\n", caps);
        if (logF) fclose(logF);
        return 0;
    }

    // ── Test 4: GET_KERNEL_BASE ─────────────────────────────────────────────
    uint64_t kernelBase = AUTH_VMCALL(HV_HYPERCALL_GET_KERNEL_BASE, 0, 0, 0);
    if (!optJson) {
        LOG("[+] [0x0010] GET_KERNEL_BASE: 0x%016llX\n", kernelBase);
    }
    if (optKernelBase) {
        if (optJson) printf("{\"kernel_base\": \"0x%016llX\"}\n", kernelBase);
        if (logF) fclose(logF);
        return 0;
    }

    // ── Test 5: GET_CR3 & Current Process TRANSLATE ─────────────────────────
    uint64_t currentCr3 = AUTH_VMCALL(HV_HYPERCALL_GET_CR3, 0, 0, 0);
    if (!optJson) LOG("[+] [0x0004] GET_CR3 (Current Process PID=%lu): 0x%016llX\n", GetCurrentProcessId(), currentCr3);

    // Test virtual translation on our own stack pointer
    uint64_t testVa = (uint64_t)(uintptr_t)&testVa;
    uint64_t testPa = AUTH_VMCALL(HV_HYPERCALL_TRANSLATE, currentCr3, testVa, 0);
    if (!optJson) LOG("[+] [0x0003] TRANSLATE (VA 0x%016llX): PA 0x%016llX\n", testVa, testPa);

    // ── Test 6: READ_PHYSICAL (Read back from translated stack PA) ──────────
    uint8_t physBuf[64] = {0};
    uint64_t physRes = AUTH_VMCALL(HV_HYPERCALL_READ_PHYS, testPa, (uintptr_t)physBuf, sizeof(physBuf));
    if (!optJson) {
        LOG("[+] [0x0001] READ_PHYS (PA 0x%016llX, 64 bytes): Status=0x%llX\n", testPa, physRes);
        if (physRes == HV_STATUS_SUCCESS) {
            HexDump(physBuf, sizeof(physBuf), testPa);
        }
    }

    // ── Test 7: READ_VIRT (Read self stack directly via atomic hypercall) ───
    uint8_t virtBuf[64] = {0};
    uint64_t pidAndSize = ((uint64_t)sizeof(virtBuf) << 32) | 0; // PID=0 (current)
    uint64_t virtRes = AUTH_VMCALL(HV_HYPERCALL_READ_VIRT, pidAndSize, testVa, (uintptr_t)virtBuf);
    if (!optJson) {
        LOG("[+] [0x000E] READ_VIRT (PID=0, VA 0x%016llX, 64 bytes): Status=0x%llX\n", testVa, virtRes);
        if (virtRes == HV_STATUS_SUCCESS) {
            HexDump(virtBuf, sizeof(virtBuf), testVa);
        }
    }

    // ── Custom Read Physical Option ─────────────────────────────────────────
    if (optReadPhys) {
        if (readLen > 4096) readLen = 4096;
        uint8_t *customBuf = (uint8_t *)malloc(readLen);
        if (customBuf) {
            memset(customBuf, 0, readLen);
            uint64_t r = AUTH_VMCALL(HV_HYPERCALL_READ_PHYS, targetPa, (uintptr_t)customBuf, readLen);
            if (!optJson) {
                printf("[+] Physical Memory Dump at 0x%016llX (%u bytes, status 0x%llX):\n", targetPa, readLen, r);
                HexDump(customBuf, readLen, targetPa);
            } else {
                printf("{\"pa\": \"0x%016llX\", \"status\": %llu}\n", targetPa, r);
            }
            free(customBuf);
        }
        if (logF) fclose(logF);
        return 0;
    }

    // ── Custom Read Virtual Option ──────────────────────────────────────────
    if (optReadVirt) {
        if (readLen > 4096) readLen = 4096;
        uint8_t *customBuf = (uint8_t *)malloc(readLen);
        if (customBuf) {
            memset(customBuf, 0, readLen);
            uint64_t pAndS = ((uint64_t)readLen << 32) | targetPid;
            uint64_t r = AUTH_VMCALL(HV_HYPERCALL_READ_VIRT, pAndS, targetVa, (uintptr_t)customBuf);
            if (!optJson) {
                printf("[+] Virtual Memory Dump (PID=%u, VA=0x%016llX, %u bytes, status 0x%llX):\n", targetPid, targetVa, readLen, r);
                HexDump(customBuf, readLen, targetVa);
            } else {
                printf("{\"pid\": %u, \"va\": \"0x%016llX\", \"status\": %llu}\n", targetPid, targetVa, r);
            }
            free(customBuf);
        }
        if (logF) fclose(logF);
        return 0;
    }

    // ── Test 8: INVALIDATE_EPT ──────────────────────────────────────────────
    if (optInvept || optAll) {
        uint64_t inveptRes = AUTH_VMCALL(HV_HYPERCALL_INVALIDATE_EPT, 0, 0, 0);
        if (!optJson) LOG("[+] [0x0007] INVALIDATE_EPT: Status=0x%llX\n", inveptRes);
    }

    // ── Benchmarking ────────────────────────────────────────────────────────
    if (optBench || optAll) {
        if (!optJson) LOG("\n[*] Benchmarking Authenticated VMCALL Latency (%u iterations)...\n", benchIterations);
        uint64_t minCycles = (uint64_t)-1;
        uint64_t maxCycles = 0;
        uint64_t totalCycles = 0;

        for (uint32_t it = 0; it < benchIterations; it++) {
            uint64_t words[6] = { sessionMagic, HV_HYPERCALL_SELFTEST, 0, 0, 0, seq };
            uint64_t mac = HvMacTuple(key0, key1, words);
            
            uint64_t t0 = __rdtsc();
            RawVmcall(sessionMagic, HV_HYPERCALL_SELFTEST, 0, 0, mac, 0);
            uint64_t t1 = __rdtsc();
            seq++;

            uint64_t delta = t1 - t0;
            if (delta < minCycles) minCycles = delta;
            if (delta > maxCycles) maxCycles = delta;
            totalCycles += delta;
        }

        double avgCycles = (double)totalCycles / benchIterations;
        if (!optJson) {
            LOG("[+] Benchmark Results:\n");
            LOG("    Min Latency: %llu cycles\n", minCycles);
            LOG("    Max Latency: %llu cycles\n", maxCycles);
            LOG("    Avg Latency: %.1f cycles\n\n", avgCycles);
        } else {
            printf("{\"min_cycles\": %llu, \"max_cycles\": %llu, \"avg_cycles\": %.1f}\n", minCycles, maxCycles, avgCycles);
        }
    }

    if (!optJson) {
        LOG("=================================================================\n");
        LOG("[+] FULL DIAGNOSTIC SUITE COMPLETED SUCCESSFULLY!\n");
        LOG("=================================================================\n");
    }

    if (logF) fclose(logF);
    return 0;
}
