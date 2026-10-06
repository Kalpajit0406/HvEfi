// hv_status.h — the hypercall return codes, in one place.
//
// WHY A SEPARATE FILE
//   These codes are the wire contract: a guest sees the number, so the driver,
//   the EFI hypervisor and the user-mode client must all read the same ones.
//   They used to be a duplicated #define block in each tree's hvdefs.h, and
//   the user-mode side (Hypervisor/hv_vmclient.c) could not see either copy —
//   it reached for HV_STATUS_INVALID_CALL and the name simply did not exist
//   there. HvLauncher.exe therefore did not compile, and nothing noticed: the
//   launcher is built by no gate and by neither verified build.
//
//   This header is deliberately dependency-free (only UINT64, which every
//   includer already has by this point) so it can be included from a kernel
//   header, an EDK2 module and a user-mode client alike. That also keeps
//   hv_contract.h's documented include position intact — it must follow
//   hv_copy.h and the EPT constants, so it cannot be hoisted to the top of
//   hvdefs.h to carry these instead.
//
// VALUES ARE WIRE FORMAT. Do not renumber. tools/unit/hvauth_cases.h pins
// SUCCESS and NOT_OURS at run time, and the two trees compile the same set of
// cases against their own copy.

#ifndef HV_STATUS_H
#define HV_STATUS_H

#define HV_STATUS_SUCCESS               0
#define HV_STATUS_INVALID_CALL          1
#define HV_STATUS_INVALID_PARAM         2
#define HV_STATUS_ACCESS_DENIED         3
#define HV_STATUS_SELFTEST_FAIL         4

// Internal sentinel: the VMCALL was not addressed to us (magic matched neither
// the boot magic nor the session magic). The exit handler turns this into a #UD
// for the guest instead of writing it to RAX. Never crosses the hypercall
// interface — it is what the handler sees, not what a guest is told.
#define HV_STATUS_NOT_OURS              ((UINT64)-2)

#endif // HV_STATUS_H