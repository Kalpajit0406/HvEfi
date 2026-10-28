// src/vmcall.rs - Dynamic VMCALL execution stub and CPUID probe.

use std::sync::atomic::{AtomicPtr, Ordering};
use windows_sys::Win32::Foundation::STATUS_ILLEGAL_INSTRUCTION;
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, FlushInstructionCache, EXCEPTION_CONTINUE_EXECUTION,
    EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, SetThreadAffinityMask, Sleep,
};

static VMCALL_STUB: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());

type VmcallFn = unsafe extern "win64" fn(
    magic: u64,
    id: u64,
    p1: u64,
    p2: u64,
    mac: u64,
    p3: u64,
) -> u64;

unsafe extern "system" fn vectored_exception_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    if info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    unsafe {
        let record = (*info).ExceptionRecord;
        let context = (*info).ContextRecord;
        if record.is_null() || context.is_null() {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        let code = (*record).ExceptionCode;
        let stub = VMCALL_STUB.load(Ordering::Relaxed);

        // If vmcall caused #UD (STATUS_ILLEGAL_INSTRUCTION) inside our stub
        if code as u32 == STATUS_ILLEGAL_INSTRUCTION as u32 && !stub.is_null() {
            let rip = (*context).Rip;
            // Stub layout:
            // offset 0..4: mov r10, [rsp+28h] (5 bytes)
            // offset 5..9: mov r11, [rsp+30h] (5 bytes)
            // offset 10..12: vmcall (3 bytes: 0F 01 C1)
            // offset 13: ret (1 byte: C3)
            let vmcall_addr = stub as u64 + 10;
            if rip == vmcall_addr {
                (*context).Rax = u64::MAX;
                (*context).Rip = vmcall_addr + 3; // jump to 'ret'
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    EXCEPTION_CONTINUE_SEARCH
}

pub fn build_vmcall_stub() -> bool {
    let current = VMCALL_STUB.load(Ordering::Acquire);
    if !current.is_null() {
        return true;
    }

    unsafe {
        let mem = VirtualAlloc(
            std::ptr::null_mut(),
            4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if mem.is_null() {
            return false;
        }

        let stub_bytes: [u8; 14] = [
            0x4C, 0x8B, 0x54, 0x24, 0x28, // mov r10, [rsp+28h]
            0x4C, 0x8B, 0x5C, 0x24, 0x30, // mov r11, [rsp+30h]
            0x0F, 0x01, 0xC1,             // vmcall
            0xC3,                         // ret
        ];

        std::ptr::copy_nonoverlapping(stub_bytes.as_ptr(), mem as *mut u8, stub_bytes.len());

        let mut old_protect = 0;
        if VirtualProtect(mem, 4096, PAGE_EXECUTE_READ, &mut old_protect) == 0 {
            return false;
        }

        FlushInstructionCache(GetCurrentProcess(), mem, 4096);

        // Register vectored exception handler
        AddVectoredExceptionHandler(1, Some(vectored_exception_handler));

        VMCALL_STUB.store(mem as *mut u8, Ordering::Release);
        true
    }
}

pub fn raw_vmcall(magic: u64, id: u64, p1: u64, p2: u64, mac: u64, p3: u64) -> u64 {
    if !build_vmcall_stub() {
        return u64::MAX;
    }
    let stub = VMCALL_STUB.load(Ordering::Relaxed);
    if stub.is_null() {
        return u64::MAX;
    }

    unsafe {
        let func: VmcallFn = std::mem::transmute(stub);
        func(magic, id, p1, p2, mac, p3)
    }
}

pub fn auth_vmcall(
    session_magic: u64,
    key0: u64,
    key1: u64,
    seq: &mut u64,
    id: u64,
    p1: u64,
    p2: u64,
    p3: u64,
) -> u64 {
    let words = [session_magic, id, p1, p2, 0, *seq];
    let mac = crate::siphash::hv_mac_tuple(key0, key1, &words);
    let ret = raw_vmcall(session_magic, id, p1, p2, mac, p3);
    *seq += 1;
    ret
}

pub fn get_processor_count() -> u32 {
    unsafe {
        let mut si: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut si);
        si.dwNumberOfProcessors
    }
}

pub fn check_canary_cpuid(num_processors: u32) -> u32 {
    let mut active = 0;
    let limit = num_processors.min(64);
    unsafe {
        let cur_thread = GetCurrentThread();
        for i in 0..limit {
            SetThreadAffinityMask(cur_thread, 1usize << i);
            Sleep(1);
            let res = core::arch::x86_64::__cpuid_count(0x13371337, 0);
            if res.eax == 0x564D5831 {
                active += 1;
            }
        }
        SetThreadAffinityMask(cur_thread, usize::MAX);
    }
    active
}

pub fn detect_vmcall(boot_magic: u64, num_processors: u32) -> (u32, u64) {
    let mut active_vmcall = 0;
    let mut detected_nonce = 0;
    let limit = num_processors.min(64);

    unsafe {
        let cur_thread = GetCurrentThread();
        for i in 0..limit {
            SetThreadAffinityMask(cur_thread, 1usize << i);
            Sleep(1);
            let res = raw_vmcall(boot_magic, crate::hvdefs::HV_HYPERCALL_DETECT, 0, 0, 0, 0);
            if res != u64::MAX && res != u64::MAX - 1 && res != crate::hvdefs::HV_STATUS_NOT_OURS && res > 0xFF {
                active_vmcall += 1;
                detected_nonce = res;
            }
        }
        SetThreadAffinityMask(cur_thread, usize::MAX);
    }

    (active_vmcall, detected_nonce)
}
