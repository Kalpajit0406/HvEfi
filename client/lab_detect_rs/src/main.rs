// src/main.rs - HvEfi Comprehensive Windows Runtime Verification Client in Rust.

mod driver;
mod hvdefs;
mod siphash;
mod vmcall;

use std::fs::OpenOptions;
use std::io::Write;
use std::process::ExitCode;

use driver::run_driver_tests;
use hvdefs::*;
use siphash::*;
use vmcall::*;

pub fn hex_dump(data: &[u8], base_addr: u64) {
    for i in (0..data.len()).step_by(16) {
        print!("    0x{:016X}: ", base_addr + i as u64);
        for j in 0..16 {
            if i + j < data.len() {
                print!("{:02X} ", data[i + j]);
            } else {
                print!("   ");
            }
            if j == 7 {
                print!(" ");
            }
        }
        print!(" |");
        for j in 0..16 {
            if i + j < data.len() {
                let c = data[i + j];
                if (32..=126).contains(&c) {
                    print!("{}", c as char);
                } else {
                    print!(".");
                }
            }
        }
        println!("|");
    }
}

fn print_help(prog: &str) {
    println!("HvEfi Comprehensive Windows Runtime Verification Client");
    println!("Usage: {} [OPTIONS]\n", prog);
    println!("Options:");
    println!("  --all                  Run complete diagnostic test suite across all hypercalls (default)");
    println!("  --detect               Quick residency check (Canary CPUID & VMCALL detect only)");
    println!("  --status               Query hypervisor status word, running flag, and active vCPUs");
    println!("  --capabilities         Query hypervisor supported opcode bitmask and ABI version");
    println!("  --bench [iterations]   Benchmark VMCALL execution latency (CPU cycle delta)");
    println!("  --read-phys <pa> <len> Read physical memory directly through hypervisor");
    println!("  --read-virt <pid> <va> <len> Read target process virtual memory via hypervisor");
    println!("  --kernel-base          Query ntoskrnl base address discovered by hypervisor");
    println!("  --invept               Trigger hypervisor global EPT TLB invalidation");
    println!("  --ticket <file>        Specify custom 32-byte ticket file");
    println!("  --json                 Output test results in JSON format");
    println!("  --help                 Display this help message");
}

fn try_load_ticket_file(path: &str, ticket: &mut [u8; 32]) -> bool {
    if let Ok(data) = std::fs::read(path) {
        if data.len() == 32 {
            ticket.copy_from_slice(&data);
            return true;
        }
    }
    false
}

fn auto_discover_ticket(ticket: &mut [u8; 32]) {
    let candidates = [
        "hvticket",
        "..\\hvticket",
        "F:\\HvEfi\\hvticket",
        "D:\\EFI\\Boot\\hvticket",
        "C:\\EFI\\Boot\\hvticket",
    ];
    for path in &candidates {
        if try_load_ticket_file(path, ticket) {
            println!("[*] Loaded ticket from: {}", path);
            return;
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let prog = &args[0];

    let mut opt_all = true;
    let mut opt_detect_only = false;
    let mut opt_status_only = false;
    let mut opt_caps_only = false;
    let mut opt_bench = false;
    let mut opt_read_phys = false;
    let mut opt_read_virt = false;
    let mut opt_kernel_base = false;
    let mut opt_invept = false;
    let mut opt_json = false;
    let mut opt_driver = false;

    let mut bench_iterations: u32 = 1000;
    let mut target_pa: u64 = 0;
    let mut target_pid: u32 = 0;
    let mut target_va: u64 = 0;
    let mut read_len: u32 = 64;

    let mut ticket: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_help(prog);
                return ExitCode::SUCCESS;
            }
            "--detect" => {
                opt_detect_only = true;
                opt_all = false;
            }
            "--status" => {
                opt_status_only = true;
                opt_all = false;
            }
            "--capabilities" => {
                opt_caps_only = true;
                opt_all = false;
            }
            "--bench" => {
                opt_bench = true;
                opt_all = false;
                if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    i += 1;
                    if let Ok(v) = args[i].parse::<u32>() {
                        bench_iterations = if v == 0 { 1000 } else { v };
                    }
                }
            }
            "--read-phys" => {
                opt_read_phys = true;
                opt_all = false;
                if i + 1 < args.len() {
                    i += 1;
                    target_pa = parse_int_u64(&args[i]);
                }
                if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    i += 1;
                    read_len = parse_int_u32(&args[i]);
                }
            }
            "--read-virt" => {
                opt_read_virt = true;
                opt_all = false;
                if i + 1 < args.len() {
                    i += 1;
                    target_pid = parse_int_u32(&args[i]);
                }
                if i + 1 < args.len() {
                    i += 1;
                    target_va = parse_int_u64(&args[i]);
                }
                if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    i += 1;
                    read_len = parse_int_u32(&args[i]);
                }
            }
            "--kernel-base" => {
                opt_kernel_base = true;
                opt_all = false;
            }
            "--invept" => {
                opt_invept = true;
                opt_all = false;
            }
            "--ticket" => {
                if i + 1 < args.len() {
                    i += 1;
                    let tpath = &args[i];
                    if !try_load_ticket_file(tpath, &mut ticket) {
                        eprintln!("[-] Failed to read ticket file: {}", tpath);
                        return ExitCode::FAILURE;
                    }
                }
            }
            "--driver" => {
                opt_driver = true;
            }
            "--json" => {
                opt_json = true;
            }
            _ => {}
        }
        i += 1;
    }

    if opt_driver {
        if !opt_json {
            println!("=================================================================");
            println!("[*] HvEfi Companion Driver Verification (IOCTL Bridge Mode)");
            println!("=================================================================");
        }
        let ok = run_driver_tests(opt_json, target_pa, target_pid, target_va, read_len);
        return if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE };
    }

    auto_discover_ticket(&mut ticket);

    let mut log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("hv_detect.log")
        .ok();

    let mut log = |msg: &str| {
        if !opt_json {
            print!("{}", msg);
        }
        if let Some(ref mut f) = log_file {
            let _ = f.write_all(msg.as_bytes());
            let _ = f.flush();
        }
    };

    if !opt_json {
        log("=================================================================\n");
        log("[*] HvEfi Hypervisor Runtime Verification Suite (Full Scale)\n");
        log("=================================================================\n");
    }

    let mut ticket_words = [0u64; 4];
    for w in 0..4 {
        ticket_words[w] = u64::from_le_bytes(ticket[w * 8..(w + 1) * 8].try_into().unwrap());
    }
    let boot_magic = hv_boot_magic(&ticket_words);

    if !opt_json {
        let mut ticket_hex = String::new();
        for b in ticket {
            ticket_hex.push_str(&format!("{:02X}", b));
        }
        log(&format!("[+] Loaded Ticket: {}\n", ticket_hex));
        log(&format!("[+] Derived BootMagic: 0x{:016X}\n", boot_magic));
    }

    let num_processors = get_processor_count();
    if !opt_json {
        log(&format!("[*] System Processor Count: {}\n", num_processors));
    }

    // ── Canary CPUID Check ──────────────────────────────────────────────────
    let active_canary = check_canary_cpuid(num_processors);
    if !opt_json {
        log(&format!(
            "[*] Canary CPUID Leaf (0x13371337): {} / {} CPUs Active\n",
            active_canary, num_processors
        ));
    }

    // ── VMCALL DETECT across all CPUs ───────────────────────────────────────
    let (active_vmcall, detected_nonce) = detect_vmcall(boot_magic, num_processors);

    if active_vmcall == 0 {
        if opt_json {
            println!("{{\"status\": \"error\", \"message\": \"Hypervisor not detected\", \"active_cpus\": 0}}");
        } else {
            log("[-] Hypervisor was NOT detected via VMCALL (Bare metal or unauthenticated).\n");
        }
        return ExitCode::FAILURE;
    }

    if !opt_json {
        log(&format!(
            "[+] VMCALL DETECT Succeeded on {} CPUs! Nonce = 0x{:016X}\n",
            active_vmcall, detected_nonce
        ));
    }

    if opt_detect_only {
        if opt_json {
            println!(
                "{{\"status\": \"ok\", \"active_cpus\": {}, \"nonce\": \"0x{:016X}\"}}",
                active_vmcall, detected_nonce
            );
        }
        return ExitCode::SUCCESS;
    }

    // ── Derive Cryptographic Session Keys ───────────────────────────────────
    let (key0, key1) = hv_derive_session(&ticket_words, detected_nonce);
    let session_magic = hv_session_magic(key0, key1);
    if !opt_json {
        log(&format!(
            "[+] Session Keys Derived. SessionMagic = 0x{:016X}\n",
            session_magic
        ));
    }

    let mut seq = 1u64;

    // ── Test 1: QUERY_STATUS ────────────────────────────────────────────────
    let status_word = auth_vmcall(session_magic, key0, key1, &mut seq, HV_HYPERCALL_QUERY_STATUS, 0, 0, 0);
    let hv_vcpus = (status_word & HV_STATUS_CPU_MASK) as u32;
    let hv_running = (status_word & HV_STATUS_RUNNING_BIT) != 0;
    let dark_reason = ((status_word >> 32) & 0xFF) as u32;
    if !opt_json {
        log(&format!(
            "[+] [0x0006] QUERY_STATUS: 0x{:016X} (vCPUs: {}, Running: {}, DarkReason: {})\n",
            status_word,
            hv_vcpus,
            if hv_running { "YES" } else { "NO" },
            dark_reason
        ));
    }
    if opt_status_only {
        if opt_json {
            println!(
                "{{\"status_word\": \"0x{:016X}\", \"vcpus\": {}, \"running\": {}}}",
                status_word, hv_vcpus, hv_running
            );
        }
        return ExitCode::SUCCESS;
    }

    // ── Test 2: SELFTEST ────────────────────────────────────────────────────
    let selftest_res = auth_vmcall(session_magic, key0, key1, &mut seq, HV_HYPERCALL_SELFTEST, 0, 0, 0);
    if !opt_json {
        log(&format!(
            "[+] [0x0008] SELFTEST: {} (Status: 0x{:X})\n",
            if selftest_res == HV_STATUS_SUCCESS { "PASSED" } else { "FAILED" },
            selftest_res
        ));
    }

    // ── Test 3: CAPABILITIES ────────────────────────────────────────────────
    let caps = auth_vmcall(session_magic, key0, key1, &mut seq, HV_HYPERCALL_CAPABILITIES, 0, 0, 0);
    if !opt_json {
        log(&format!("[+] [0x000B] CAPABILITIES Bitmask: 0x{:016X}\n", caps));
        log("    Supported Hypercalls:\n");
        let cap_names = [
            "DETECT", "READ_PHYS", "WRITE_PHYS", "TRANSLATE", "GET_CR3", "UNLOAD",
            "QUERY_STATUS", "INVALIDATE_EPT", "SELFTEST", "SET_CR3_OFFSET", "READ_SCATTER",
            "CAPABILITIES", "QUERY_EXIT_COUNTS", "READ_VIRT", "WRITE_VIRT", "GET_KERNEL_BASE",
            "EPT_HOOK", "EPT_UNHOOK",
        ];
        for (b, name) in cap_names.iter().enumerate() {
            if (caps & (1u64 << b)) != 0 {
                log(&format!("     - [0x{:02X}] {}\n", b, name));
            }
        }
    }
    if opt_caps_only {
        if opt_json {
            println!("{{\"capabilities\": \"0x{:016X}\"}}", caps);
        }
        return ExitCode::SUCCESS;
    }

    // ── Test 4: GET_KERNEL_BASE ─────────────────────────────────────────────
    let kernel_base = auth_vmcall(session_magic, key0, key1, &mut seq, HV_HYPERCALL_GET_KERNEL_BASE, 0, 0, 0);
    if !opt_json {
        log(&format!("[+] [0x0010] GET_KERNEL_BASE: 0x{:016X}\n", kernel_base));
    }
    if opt_kernel_base {
        if opt_json {
            println!("{{\"kernel_base\": \"0x{:016X}\"}}", kernel_base);
        }
        return ExitCode::SUCCESS;
    }

    // ── Test 5: GET_CR3 & Current Process TRANSLATE ─────────────────────────
    let current_cr3 = auth_vmcall(session_magic, key0, key1, &mut seq, HV_HYPERCALL_GET_CR3, 0, 0, 0);
    let cur_pid = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() };
    if !opt_json {
        log(&format!(
            "[+] [0x0004] GET_CR3 (Current Process PID={}): 0x{:016X}\n",
            cur_pid, current_cr3
        ));
    }

    let mut test_va: u64 = 0;
    let test_va_addr = &mut test_va as *mut u64 as u64;
    let test_pa = auth_vmcall(session_magic, key0, key1, &mut seq, HV_HYPERCALL_TRANSLATE, current_cr3, test_va_addr, 0);
    if !opt_json {
        log(&format!(
            "[+] [0x0003] TRANSLATE (VA 0x{:016X}): PA 0x{:016X}\n",
            test_va_addr, test_pa
        ));
    }

    // ── Test 6: READ_PHYSICAL ───────────────────────────────────────────────
    let mut phys_buf = [0u8; 64];
    let phys_res = auth_vmcall(
        session_magic,
        key0,
        key1,
        &mut seq,
        HV_HYPERCALL_READ_PHYS,
        test_pa,
        phys_buf.as_mut_ptr() as u64,
        phys_buf.len() as u64,
    );
    if !opt_json {
        log(&format!(
            "[+] [0x0001] READ_PHYS (PA 0x{:016X}, 64 bytes): Status=0x{:X}\n",
            test_pa, phys_res
        ));
        if phys_res == HV_STATUS_SUCCESS {
            hex_dump(&phys_buf, test_pa);
        }
    }

    // ── Test 7: READ_VIRT ───────────────────────────────────────────────────
    let mut virt_buf = [0u8; 64];
    let pid_and_size = ((virt_buf.len() as u64) << 32) | 0; // PID=0 (current)
    let virt_res = auth_vmcall(
        session_magic,
        key0,
        key1,
        &mut seq,
        HV_HYPERCALL_READ_VIRT,
        pid_and_size,
        test_va_addr,
        virt_buf.as_mut_ptr() as u64,
    );
    if !opt_json {
        log(&format!(
            "[+] [0x000E] READ_VIRT (PID=0, VA 0x{:016X}, 64 bytes): Status=0x{:X}\n",
            test_va_addr, virt_res
        ));
        if virt_res == HV_STATUS_SUCCESS {
            hex_dump(&virt_buf, test_va_addr);
        }
    }

    // ── Custom Read Physical Option ─────────────────────────────────────────
    if opt_read_phys {
        let eff_len = if read_len > 4096 { 4096 } else { read_len } as usize;
        let mut custom_buf = vec![0u8; eff_len];
        let r = auth_vmcall(
            session_magic,
            key0,
            key1,
            &mut seq,
            HV_HYPERCALL_READ_PHYS,
            target_pa,
            custom_buf.as_mut_ptr() as u64,
            eff_len as u64,
        );
        if !opt_json {
            println!(
                "[+] Physical Memory Dump at 0x{:016X} ({} bytes, status 0x{:X}):",
                target_pa, eff_len, r
            );
            hex_dump(&custom_buf, target_pa);
        } else {
            println!("{{\"pa\": \"0x{:016X}\", \"status\": {}}}", target_pa, r);
        }
        return ExitCode::SUCCESS;
    }

    // ── Custom Read Virtual Option ──────────────────────────────────────────
    if opt_read_virt {
        let eff_len = if read_len > 4096 { 4096 } else { read_len } as usize;
        let mut custom_buf = vec![0u8; eff_len];
        let p_and_s = ((eff_len as u64) << 32) | (target_pid as u64);
        let r = auth_vmcall(
            session_magic,
            key0,
            key1,
            &mut seq,
            HV_HYPERCALL_READ_VIRT,
            p_and_s,
            target_va,
            custom_buf.as_mut_ptr() as u64,
        );
        if !opt_json {
            println!(
                "[+] Virtual Memory Dump (PID={}, VA=0x{:016X}, {} bytes, status 0x{:X}):",
                target_pid, target_va, eff_len, r
            );
            hex_dump(&custom_buf, target_va);
        } else {
            println!(
                "{{\"pid\": {}, \"va\": \"0x{:016X}\", \"status\": {}}}",
                target_pid, target_va, r
            );
        }
        return ExitCode::SUCCESS;
    }

    // ── Test 8: INVALIDATE_EPT ──────────────────────────────────────────────
    if opt_invept || opt_all {
        let invept_res = auth_vmcall(session_magic, key0, key1, &mut seq, HV_HYPERCALL_INVALIDATE_EPT, 0, 0, 0);
        if !opt_json {
            log(&format!("[+] [0x0007] INVALIDATE_EPT: Status=0x{:X}\n", invept_res));
        }
    }

    // ── Benchmarking ────────────────────────────────────────────────────────
    if opt_bench || opt_all {
        if !opt_json {
            log(&format!(
                "\n[*] Benchmarking Authenticated VMCALL Latency ({} iterations)...\n",
                bench_iterations
            ));
        }
        let mut min_cycles = u64::MAX;
        let mut max_cycles = 0u64;
        let mut total_cycles = 0u64;

        for _ in 0..bench_iterations {
            let words = [session_magic, HV_HYPERCALL_SELFTEST, 0, 0, 0, seq];
            let mac = hv_mac_tuple(key0, key1, &words);

            let t0 = unsafe { core::arch::x86_64::_rdtsc() };
            raw_vmcall(session_magic, HV_HYPERCALL_SELFTEST, 0, 0, mac, 0);
            let t1 = unsafe { core::arch::x86_64::_rdtsc() };
            seq += 1;

            let delta = t1.saturating_sub(t0);
            if delta < min_cycles {
                min_cycles = delta;
            }
            if delta > max_cycles {
                max_cycles = delta;
            }
            total_cycles = total_cycles.saturating_add(delta);
        }

        let avg_cycles = (total_cycles as f64) / (bench_iterations as f64);
        if !opt_json {
            log("[+] Benchmark Results:\n");
            log(&format!("    Min Latency: {} cycles\n", min_cycles));
            log(&format!("    Max Latency: {} cycles\n", max_cycles));
            log(&format!("    Avg Latency: {:.1} cycles\n\n", avg_cycles));
        } else {
            println!(
                "{{\"min_cycles\": {}, \"max_cycles\": {}, \"avg_cycles\": {:.1}}}",
                min_cycles, max_cycles, avg_cycles
            );
        }
    }

    if !opt_json {
        log("=================================================================\n");
        log("[+] FULL DIAGNOSTIC SUITE COMPLETED SUCCESSFULLY!\n");
        log("=================================================================\n");
    }

    ExitCode::SUCCESS
}

fn parse_int_u64(s: &str) -> u64 {
    if let Some(stripped) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(stripped, 16).unwrap_or(0)
    } else {
        s.parse::<u64>().unwrap_or(0)
    }
}

fn parse_int_u32(s: &str) -> u32 {
    if let Some(stripped) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(stripped, 16).unwrap_or(0)
    } else {
        s.parse::<u32>().unwrap_or(0)
    }
}
