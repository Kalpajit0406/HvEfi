// src/hvdefs.rs - Hypercall IDs, status codes, and constants.
//
// Matches shared/hv_status.h and hypervisor/hvdefs.h.

#![allow(dead_code)]

pub const HV_HYPERCALL_DETECT: u64 = 0x0000;
pub const HV_HYPERCALL_READ_PHYS: u64 = 0x0001;
pub const HV_HYPERCALL_WRITE_PHYS: u64 = 0x0002;
pub const HV_HYPERCALL_TRANSLATE: u64 = 0x0003;
pub const HV_HYPERCALL_GET_CR3: u64 = 0x0004;
pub const HV_HYPERCALL_UNLOAD: u64 = 0x0005;
pub const HV_HYPERCALL_QUERY_STATUS: u64 = 0x0006;
pub const HV_HYPERCALL_INVALIDATE_EPT: u64 = 0x0007;
pub const HV_HYPERCALL_SELFTEST: u64 = 0x0008;
pub const HV_HYPERCALL_SET_CR3_OFFSET: u64 = 0x000A;
pub const HV_HYPERCALL_CAPABILITIES: u64 = 0x000B;
pub const HV_HYPERCALL_QUERY_EXIT_COUNTS: u64 = 0x000C;
pub const HV_HYPERCALL_READ_VIRT: u64 = 0x000E;
pub const HV_HYPERCALL_WRITE_VIRT: u64 = 0x000F;
pub const HV_HYPERCALL_GET_KERNEL_BASE: u64 = 0x0010;
pub const HV_HYPERCALL_EPT_HOOK: u64 = 0x0011;
pub const HV_HYPERCALL_EPT_UNHOOK: u64 = 0x0012;

pub const HV_STATUS_SUCCESS: u64 = 0;
pub const HV_STATUS_INVALID_CALL: u64 = 1;
pub const HV_STATUS_INVALID_PARAM: u64 = 2;
pub const HV_STATUS_ACCESS_DENIED: u64 = 3;
pub const HV_STATUS_SELFTEST_FAIL: u64 = 4;
pub const HV_STATUS_NOT_OURS: u64 = u64::MAX - 1; // (UINT64)-2

pub const HV_STATUS_CPU_MASK: u64 = 0xFFFF;
pub const HV_STATUS_RUNNING_BIT: u64 = 1 << 16;
