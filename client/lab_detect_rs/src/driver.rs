// src/driver.rs - Windows kernel companion driver IOCTL interface (\\.\HvDrv).

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileA, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

const HV_USER_DEVICE_NAME: &[u8] = b"\\\\.\\HvDrv\0";

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

const HV_DEVICE_TYPE: u32 = 0x8337;
const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;
const FILE_READ_ACCESS: u32 = 0x0001;
const FILE_WRITE_ACCESS: u32 = 0x0002;

const IOCTL_HV_DETECT: u32 = ctl_code(HV_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_HV_QUERY_STATUS: u32 = ctl_code(HV_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_HV_SELFTEST: u32 = ctl_code(HV_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_HV_CAPABILITIES: u32 = ctl_code(HV_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_HV_READ_PHYS: u32 = ctl_code(HV_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
const IOCTL_HV_GET_KERNEL_BASE: u32 = ctl_code(HV_DEVICE_TYPE, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS);

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct HvIoctlDetect {
    pub ticket: [u8; 32],
    pub nonce: u64,
    pub active_cpu_count: u32,
    pub canary_active: u32,
    pub status: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct HvIoctlStatus {
    pub raw_status_word: u64,
    pub vcpu_count: u32,
    pub running: u32,
    pub dark_reason: u32,
    pub tsc_scale: u32,
    pub status: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct HvIoctlCapabilities {
    pub supported_bitmask: u64,
    pub abi_version: u32,
    pub status: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct HvIoctlKernelBase {
    pub kernel_base: u64,
    pub status: u64,
}

#[repr(C)]
pub struct HvIoctlReadPhys {
    pub physical_address: u64,
    pub size: u32,
    pub buffer: [u8; 4096],
    pub status: u64,
}

impl Default for HvIoctlReadPhys {
    fn default() -> Self {
        Self {
            physical_address: 0,
            size: 0,
            buffer: [0u8; 4096],
            status: 0,
        }
    }
}

pub fn run_driver_tests(
    opt_json: bool,
    target_pa: u64,
    _target_pid: u32,
    _target_va: u64,
    read_len: u32,
) -> bool {
    unsafe {
        let h_dev = CreateFileA(
            HV_USER_DEVICE_NAME.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );

        if h_dev == INVALID_HANDLE_VALUE {
            if !opt_json {
                println!(
                    "[-] Failed to open device \\\\.\\HvDrv (Error={}). Ensure HvDrv service is started.",
                    GetLastError()
                );
            }
            return false;
        }

        if !opt_json {
            println!("[+] Successfully opened handle to \\\\.\\HvDrv");
        }

        let mut bytes: u32 = 0;

        // 1. IOCTL_HV_DETECT
        let mut det = HvIoctlDetect::default();
        if DeviceIoControl(
            h_dev,
            IOCTL_HV_DETECT,
            &det as *const _ as *const _,
            std::mem::size_of::<HvIoctlDetect>() as u32,
            &mut det as *mut _ as *mut _,
            std::mem::size_of::<HvIoctlDetect>() as u32,
            &mut bytes,
            std::ptr::null_mut(),
        ) != 0
        {
            if !opt_json {
                println!("[+] IOCTL_HV_DETECT: Nonce=0x{:016X}, Status=0x{:X}", det.nonce, det.status);
            }
        }

        // 2. IOCTL_HV_QUERY_STATUS
        let mut st = HvIoctlStatus::default();
        if DeviceIoControl(
            h_dev,
            IOCTL_HV_QUERY_STATUS,
            &st as *const _ as *const _,
            std::mem::size_of::<HvIoctlStatus>() as u32,
            &mut st as *mut _ as *mut _,
            std::mem::size_of::<HvIoctlStatus>() as u32,
            &mut bytes,
            std::ptr::null_mut(),
        ) != 0
        {
            if !opt_json {
                println!(
                    "[+] IOCTL_HV_QUERY_STATUS: VcpuCount={}, Running={}, RawStatusWord=0x{:016X}",
                    st.vcpu_count, st.running, st.raw_status_word
                );
            }
        }

        // 3. IOCTL_HV_SELFTEST
        let mut selftest_status: u64 = u64::MAX;
        if DeviceIoControl(
            h_dev,
            IOCTL_HV_SELFTEST,
            std::ptr::null(),
            0,
            &mut selftest_status as *mut _ as *mut _,
            std::mem::size_of::<u64>() as u32,
            &mut bytes,
            std::ptr::null_mut(),
        ) != 0
        {
            if !opt_json {
                println!(
                    "[+] IOCTL_HV_SELFTEST: Status=0x{:X} ({})",
                    selftest_status,
                    if selftest_status == 0 { "PASSED" } else { "FAILED" }
                );
            }
        }

        // 4. IOCTL_HV_CAPABILITIES
        let mut caps = HvIoctlCapabilities::default();
        if DeviceIoControl(
            h_dev,
            IOCTL_HV_CAPABILITIES,
            &caps as *const _ as *const _,
            std::mem::size_of::<HvIoctlCapabilities>() as u32,
            &mut caps as *mut _ as *mut _,
            std::mem::size_of::<HvIoctlCapabilities>() as u32,
            &mut bytes,
            std::ptr::null_mut(),
        ) != 0
        {
            if !opt_json {
                println!(
                    "[+] IOCTL_HV_CAPABILITIES: AbiVersion={}, SupportedBitmask=0x{:016X}",
                    caps.abi_version, caps.supported_bitmask
                );
            }
        }

        // 5. IOCTL_HV_GET_KERNEL_BASE
        let mut kb = HvIoctlKernelBase::default();
        if DeviceIoControl(
            h_dev,
            IOCTL_HV_GET_KERNEL_BASE,
            &kb as *const _ as *const _,
            std::mem::size_of::<HvIoctlKernelBase>() as u32,
            &mut kb as *mut _ as *mut _,
            std::mem::size_of::<HvIoctlKernelBase>() as u32,
            &mut bytes,
            std::ptr::null_mut(),
        ) != 0
        {
            if !opt_json {
                println!(
                    "[+] IOCTL_HV_GET_KERNEL_BASE: ntoskrnl VA=0x{:016X}, Status=0x{:X}",
                    kb.kernel_base, kb.status
                );
            }
        }

        // 6. Optional Physical Read
        if target_pa != 0 {
            let mut rp = HvIoctlReadPhys::default();
            rp.physical_address = target_pa;
            rp.size = if read_len > 4096 { 4096 } else { read_len };
            if DeviceIoControl(
                h_dev,
                IOCTL_HV_READ_PHYS,
                &rp as *const _ as *const _,
                std::mem::size_of::<HvIoctlReadPhys>() as u32,
                &mut rp as *mut _ as *mut _,
                std::mem::size_of::<HvIoctlReadPhys>() as u32,
                &mut bytes,
                std::ptr::null_mut(),
            ) != 0
            {
                if !opt_json {
                    println!(
                        "[+] IOCTL_HV_READ_PHYS: PA=0x{:016X}, Size={}, Status=0x{:X}",
                        rp.physical_address, rp.size, rp.status
                    );
                    crate::hex_dump(&rp.buffer[..rp.size as usize], rp.physical_address);
                }
            }
        }

        CloseHandle(h_dev);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioctl_read_phys_layout() {
        assert_eq!(std::mem::size_of::<HvIoctlReadPhys>(), 4120);
        let s = HvIoctlReadPhys::default();
        let base = &s as *const _ as usize;
        let buf_addr = s.buffer.as_ptr() as usize;
        let st_addr = &s.status as *const _ as usize;
        assert_eq!(buf_addr - base, 12);
        assert_eq!(st_addr - base, 4112);
    }
}
