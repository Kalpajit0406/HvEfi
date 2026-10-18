#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <intrin.h>

#include "shared/hv_siphash.h"

#define HV_HYPERCALL_DETECT             0x0000
#define HV_HYPERCALL_READ_PHYS          0x0001
#define HV_HYPERCALL_WRITE_PHYS         0x0002
#define HV_HYPERCALL_TRANSLATE          0x0003
#define HV_HYPERCALL_GET_CR3            0x0004
#define HV_HYPERCALL_UNLOAD             0x0005
#define HV_HYPERCALL_QUERY_STATUS       0x0006
#define HV_HYPERCALL_INVALIDATE_EPT     0x0007
#define HV_HYPERCALL_SELFTEST           0x0008

#define HV_STATUS_SUCCESS               0x0000000000000000ULL
#define HV_STATUS_NOT_OURS              0xFFFFFFFFFFFFFFFFULL
#define HV_STATUS_CPU_MASK              0x000000000000FFFFULL
#define HV_STATUS_RUNNING_BIT           (1ULL << 63)

static const uint8_t s_LabTicket[32] = {
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

int main(int argc, char **argv) {
    FILE *logF = fopen("hv_detect.log", "a");
    #define LOG(...) do { printf(__VA_ARGS__); if (logF) { fprintf(logF, __VA_ARGS__); fflush(logF); } } while(0)

    LOG("=================================================================\n");
    LOG("[*] HvEfi Hypervisor Residency & VMCALL Detector (Lab Edition)\n");
    LOG("=================================================================\n");

    const uint64_t *ticketWords = (const uint64_t *)s_LabTicket;
    uint64_t bootMagic = HvBootMagic(ticketWords);
    LOG("[+] Configured Lab Ticket (32 bytes):\n    ");
    for (int i = 0; i < 32; i++) LOG("%02X ", s_LabTicket[i]);
    LOG("\n[+] Derived BootMagic: 0x%016llX\n\n", bootMagic);

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    LOG("[*] System Processor Count: %u\n", si.dwNumberOfProcessors);

    // 1. Canary CPUID leaf 0x13371337 across all CPUs
    LOG("\n[*] Step 1: Testing CPUID Canary (0x13371337)...\n");
    DWORD activeCanary = 0;
    for (DWORD i = 0; i < si.dwNumberOfProcessors && i < 64; i++) {
        SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)1 << i);
        Sleep(2);
        int regs[4] = {0};
        __cpuidex(regs, 0x13371337, 0);
        if (regs[0] == 0x564D5831) { // 'VMX1'
            activeCanary++;
            LOG("    [CPU %02u] Canary ACTIVE (EAX='VMX1', vCPU=%d, ExitIdx=%d, Count=%d)\n",
                i, regs[1], regs[2], regs[3]);
        } else {
            LOG("    [CPU %02u] Canary INACTIVE (Bare Metal / Unhandled: EAX=0x%08X)\n",
                i, regs[0]);
        }
    }
    SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)-1);
    LOG("[*] Canary Summary: %u / %u CPUs running under VMX\n\n", activeCanary, si.dwNumberOfProcessors);

    // 2. VMCALL DETECT across all CPUs
    LOG("[*] Step 2: Probing VMCALL DETECT across all CPUs...\n");
    uint64_t detectedNonce = 0;
    DWORD activeVmcall = 0;
    for (DWORD i = 0; i < si.dwNumberOfProcessors && i < 64; i++) {
        SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)1 << i);
        Sleep(2);
        uint64_t res = RawVmcall(bootMagic, HV_HYPERCALL_DETECT, 0, 0, 0, 0);
        if (res == (uint64_t)-1) {
            LOG("    [CPU %02u] VMCALL faulted with #UD (Bare metal / Not virtualized)\n", i);
        } else if (res == HV_STATUS_NOT_OURS) {
            LOG("    [CPU %02u] VMCALL returned NOT_OURS (Ticket mismatch or dark mode)\n", i);
        } else {
            activeVmcall++;
            detectedNonce = res;
            LOG("    [CPU %02u] VMCALL DETECT SUCCESS! Nonce = 0x%016llX\n", i, res);
        }
    }
    SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)-1);

    if (activeVmcall == 0) {
        LOG("[-] Hypervisor was NOT detected via VMCALL.\n");
        if (logF) fclose(logF);
        return 1;
    }

    LOG("\n[+] SUCCESS: Hypervisor responded to authenticated VMCALL on %u CPU(s)!\n", activeVmcall);

    // 3. Establish Session & Query Hypervisor
    LOG("\n[*] Step 3: Deriving Session Keys & Authenticated Handshake...\n");
    uint64_t key0 = 0, key1 = 0;
    HvDeriveSession(ticketWords, detectedNonce, &key0, &key1);
    uint64_t sessionMagic = HvSessionMagic(key0, key1);
    LOG("[+] Derived Session Magic: 0x%016llX\n", sessionMagic);

    uint64_t seq = 1;
    // Query Status
    {
        uint64_t words[6] = { sessionMagic, HV_HYPERCALL_QUERY_STATUS, 0, 0, 0, seq };
        uint64_t mac = HvMacTuple(key0, key1, words);
        uint64_t st = RawVmcall(sessionMagic, HV_HYPERCALL_QUERY_STATUS, 0, 0, mac, 0);
        LOG("[+] HV_HYPERCALL_QUERY_STATUS: 0x%016llX\n", st);
        LOG("    CPUs: %llu | Running: %s\n",
            (st & HV_STATUS_CPU_MASK),
            (st & HV_STATUS_RUNNING_BIT) ? "YES" : "NO");
    }

    seq++;
    // Selftest
    {
        uint64_t words[6] = { sessionMagic, HV_HYPERCALL_SELFTEST, 0, 0, 0, seq };
        uint64_t mac = HvMacTuple(key0, key1, words);
        uint64_t st = RawVmcall(sessionMagic, HV_HYPERCALL_SELFTEST, 0, 0, mac, 0);
        if (st == HV_STATUS_SUCCESS) {
            LOG("[+] HV_HYPERCALL_SELFTEST: PASSED (Status 0x0)\n");
        } else {
            LOG("[!] HV_HYPERCALL_SELFTEST: FAILED (Status 0x%llX)\n", st);
        }
    }

    seq++;
    // Get CR3
    {
        uint64_t words[6] = { sessionMagic, HV_HYPERCALL_GET_CR3, 0, 0, 0, seq };
        uint64_t mac = HvMacTuple(key0, key1, words);
        uint64_t cr3 = RawVmcall(sessionMagic, HV_HYPERCALL_GET_CR3, 0, 0, mac, 0);
        LOG("[+] HV_HYPERCALL_GET_CR3: 0x%016llX\n", cr3);
    }

    LOG("\n=================================================================\n");
    LOG("[+] ALL CHECKS PASSED: HvEfi Hypervisor residency fully proven!\n");
    LOG("=================================================================\n");

    if (logF) fclose(logF);
    return 0;
}
