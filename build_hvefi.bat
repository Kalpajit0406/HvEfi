@echo off
rem ---------------------------------------------------------------------------
rem build_hvefi.bat - build the HvEfi DXE driver from THIS repo's sources.
rem
rem Why this script exists: the EDK2 build reads HvEfi/* from inside the EDK2
rem workspace, not from the repo. Editing the repo and then running a build
rem script that only calls `build` silently compiles whatever stale copy
rem happens to sit in the workspace - which is exactly how an old, non-driver
rem image ended up registered against \EFI\Boot\memtest.efi. This script always
rem copies the repo sources into the workspace first, so the built .efi and the
rem repo cannot drift apart.
rem
rem Usage (from the repo root, or from HvEfi\):
rem     HvEfi\build_hvefi.bat                 -> DEBUG, OvmfPkgX64.dsc
rem     set HV_EDK2_ROOT=C:\some\edk2         -> choose the workspace
rem     set HV_BUILD_TARGET=RELEASE           -> DEBUG|RELEASE
rem
rem Prerequisites: an EDK2 checkout with edksetup.bat, VS2022, and python on
rem PATH (standard EDK2 requirements). Run once with `edksetup.bat Rebuild`.
rem
rem Output: %HV_EDK2_ROOT%\Build\OvmfX64\<TARGET>_VS2022\X64\HvEfi.efi
rem That file is the *template* (it still carries the provisioning sentinels).
rem Install it with:  HvLauncher.exe --provision --efi <that path>
rem ---------------------------------------------------------------------------
setlocal

if "%HV_EDK2_ROOT%"=="" set HV_EDK2_ROOT=C:\Users\DELL\edk2
if "%HV_BUILD_TARGET%"=="" set HV_BUILD_TARGET=DEBUG

set "SRC=%~dp0"
set "DST=%HV_EDK2_ROOT%\HvEfi"

if not exist "%HV_EDK2_ROOT%\edksetup.bat" (
    echo [-] No EDK2 workspace at "%HV_EDK2_ROOT%" ^(set HV_EDK2_ROOT^)
    exit /b 1
)

echo [*] Syncing HvEfi sources:
echo       from %SRC%
echo       to   %DST%
if not exist "%DST%" mkdir "%DST%"

rem hv_efi_receipt.h is in this list because hv_efi_main.c includes it. A new
rem header that is not listed here fails the build with C1083 - loud, but a
rem header that is *only* listed in .inf's [Sources] would be a silent skip.
rem HvBoot.inf/HvBoot.c are in the list because this script builds the bridge
rem module too (see the second `build` invocation below).
for %%F in (HvEfi.inf HvBoot.inf HvBoot.c hv_efi.h hv_efi_stage.h hv_efi_receipt.h hv_efi_bootcfg.h hv_efi_main.c hv_efi_vmx.c hv_efi_ept.c hv_efi_smp.c hv_efi_hypercall.c hv_exit.c hv_vmcs.c hvdefs.h hv_asm.asm) do (
    if not exist "%SRC%%%F" (
        echo [-] Missing source: %SRC%%%F
        exit /b 1
    )
    copy /y "%SRC%%%F" "%DST%\%%F" >nul || (
        echo [-] Failed to copy %%F
        exit /b 1
    )
)

rem Verify the copies byte-for-byte. The copy loop already returns non-zero on
rem failure, so this is for the case that actually bites: a source added to the
rem repo but NOT added to the list above, which leaves the previous copy in the
rem workspace building cleanly while nobody is reading that code. A stale
rem workspace is indistinguishable from a fresh one by exit code and by output.
pushd "%SRC%"
for %%F in (HvEfi.inf HvBoot.inf HvBoot.c hv_efi.h hv_efi_stage.h hv_efi_receipt.h hv_efi_bootcfg.h hv_efi_main.c hv_efi_vmx.c hv_efi_ept.c hv_efi_smp.c hv_efi_hypercall.c hv_exit.c hv_vmcs.c hvdefs.h hv_asm.asm) do (
    fc /b "%%F" "%DST%\%%F" >nul || (
        echo [-] Post-copy verification failed: %%F differs after copy
        popd
        exit /b 1
    )
)
popd

rem Windows' COPY preserves the SOURCE's last-write time, and EDK2 decides what
rem to rebuild by comparing source mtime against the output's. So a source whose
rem mtime is older than the last build - a fresh git checkout with restored
rem timestamps, a file restored from a backup, or simply an edit made before an
rem earlier build - looks "up to date" and EDK2 skips it, then reports "- Done -"
rem with a zero exit code. That is how this script can sync new code into the
rem workspace, compile nothing, and look like a successful build.
rem
rem Bumping every synced file to "now" costs a full recompile of the HvEfi module
rem (~13 s) and removes that whole failure mode. It is deliberate: for a driver
rem whose failure mode is "the machine stopped booting", a stale-but-successful
rem build is far more expensive than thirteen seconds. Only files under HvEfi\ are
rem bumped; the MdePkg/OvmfPkg libraries in the workspace keep their incremental
rem behaviour.
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Get-ChildItem -LiteralPath '%DST%' -File | ForEach-Object { $_.LastWriteTime = Get-Date }" >nul 2>&1 || ^
    echo [!] could not bump workspace timestamps - if the build below finishes suspiciously
echo     fast, treat the artifact as unverified and check its receipt strings.

rem Shared headers live in shared/ in this repo. They are placed beside HvEfi/
rem in the EDK2 workspace so that `#include "shared/hv_contract.h"` etc. resolve
rem correctly from inside %HV_EDK2_ROOT%\HvEfi\.
set "SHARED=%SRC%shared"
if not exist "%DST%\shared" mkdir "%DST%\shared"
if not exist "%DST%\shared\HvDrv" mkdir "%DST%\shared\HvDrv"
for %%F in (hv_auth.h hv_contract.h hv_copy.h hv_ept_decision.h hv_hostidt.h hv_ptwalk.h hv_ramrange.h hv_segs.h hv_siphash.h hv_smp_index.h hv_xsave.h hv_status.h) do (
    if not exist "%SHARED%\%%F" (
        echo [-] Missing shared header: %SHARED%\%%F
        exit /b 1
    )
    copy /y "%SHARED%\%%F" "%DST%\shared\%%F" >nul || exit /b 1
)
if not exist "%SHARED%\HvDrv\hv_msr_contract.h" (
    echo [-] Missing %SHARED%\HvDrv\hv_msr_contract.h
    exit /b 1
)
copy /y "%SHARED%\HvDrv\hv_msr_contract.h" "%DST%\shared\HvDrv\hv_msr_contract.h" >nul || exit /b 1

echo [*] Building (%HV_BUILD_TARGET%) ...
pushd "%HV_EDK2_ROOT%"
rem Absolute path is deliberate: when NoDefaultCurrentDirectoryInExePath is set
rem (some CI/sandbox shells set it), cmd refuses to resolve `edksetup.bat` from
rem the current directory and the build dies with "not recognized".
call "%HV_EDK2_ROOT%\edksetup.bat" >nul
rem `call` is required: `build` resolves to the EDK2 build.bat, and invoking a
rem batch file without `call` transfers control away permanently — the script
rem then never reaches its own success/failure reporting below and silently
rem returns build.bat's exit code instead of its own.
call build -a X64 -t VS2022 -p OvmfPkg\OvmfPkgX64.dsc -m HvEfi\HvEfi.inf -b %HV_BUILD_TARGET%
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
    popd
    echo [-] Build failed ^(%RC%^)
    exit /b %RC%
)
rem The HvBoot bridge application: same workspace, same toolchain.
call build -a X64 -t VS2022 -p OvmfPkg\OvmfPkgX64.dsc -m HvEfi\HvBoot.inf -b %HV_BUILD_TARGET%
set "RC=%ERRORLEVEL%"
popd

if not "%RC%"=="0" (
    echo [-] Build failed ^(%RC%^)
    exit /b %RC%
)

set "OUT=%HV_EDK2_ROOT%\Build\OvmfX64\%HV_BUILD_TARGET%_VS2022\X64\HvEfi.efi"
set "MODOUT=%HV_EDK2_ROOT%\Build\OvmfX64\%HV_BUILD_TARGET%_VS2022\X64\HvEfi\HvEfi\OUTPUT\HvEfi.efi"
set "BOOTOUT=%HV_EDK2_ROOT%\Build\OvmfX64\%HV_BUILD_TARGET%_VS2022\X64\HvBoot.efi"
set "BOOTMODOUT=%HV_EDK2_ROOT%\Build\OvmfX64\%HV_BUILD_TARGET%_VS2022\X64\HvBoot\HvBoot\OUTPUT\HvBoot.efi"

rem EDK2's incremental build skips its final copy into the X64\ directory when
rem only that copy is missing (nothing recompiled), so a build can report success
rem and still leave no artifact. GenFw already produced the module output, so
rem copy that ourselves; the contract stays "OUT exists, or this script fails".
if not exist "%OUT%" (
    if exist "%MODOUT%" (
        echo [*] EDK2 skipped its final copy step - copying the module output.
        copy /y "%MODOUT%" "%OUT%" >nul
    )
)
if not exist "%BOOTOUT%" (
    if exist "%BOOTMODOUT%" (
        copy /y "%BOOTMODOUT%" "%BOOTOUT%" >nul
    )
)

set "MISSING=0"
if exist "%OUT%" (
    echo [+] Built: %OUT%
    echo     Install with: HvLauncher.exe --provision --efi "%OUT%"
) else (
    echo [!] Build reported success but no HvEfi.efi was produced.
    echo     Looked in: %OUT%
    echo                %MODOUT%
    set "MISSING=1"
)
if exist "%BOOTOUT%" (
    echo [+] Built: %BOOTOUT%
) else (
    echo [!] Build reported success but no HvBoot.efi was produced.
    echo     Looked in: %BOOTOUT%
    echo                %BOOTMODOUT%
    set "MISSING=1"
)

rem ── Stage the artifacts into the repo ─────────────────────────────────────
rem The repo tracks HvEfi\HvEfi.efi and HvEfi\HvBoot.efi and the documented
rem install commands read them from there. The build tree and the repo drifting
rem apart is exactly how two different cores came to exist on one disk (04:41 in
rem the repo, 05:07 in the build tree) with the documented command installing
rem the stale one.
if "%MISSING%"=="0" (
    copy /y "%OUT%" "%SRC%HvEfi.efi" >nul
    copy /y "%BOOTOUT%" "%SRC%HvBoot.efi" >nul
)

rem ── Post-build contract checks ────────────────────────────────────────────
rem The driver performs no file I/O any more (Pass 90), so it must carry no
rem receipt strings at all, and the application must carry the lines it owns.
rem A silently wrong pair - a stale core, or a core with the receipt writer still
rem in it - hardens into a wrong diagnosis on the machine, which costs boots to
rem discover. Fail here instead.
if "%MISSING%"=="0" (
    findstr /c:"HVEFI" "%OUT%" >nul 2>&1 && (
        echo [!] HvEfi.efi contains receipt strings - the driver must do no file I/O.
        set "MISSING=1"
    )
    rem Completeness. The markers are spread deliberately across the WHOLE of
    rem HvEfiDriverEntryImpl rather than clustered at the top: the whole-program
    rem optimisation truncation kept Steps 1-4 and dropped everything after them,
    rem so a check that only looked for an early string would have passed on a
    rem broken image. One marker per region means a future partial-image
    rem regression is caught by the region that actually vanished.
    for %%M in ("Step 1: VMX supported" "Step 4: Nonce generated" "Ticket read from the mailbox" "Session keys derived" "Decoy pages allocated" "EPT hiding complete" "All %%%u CPUs virtualized" "Secrets wiped from g_Hv") do (
        findstr /c:%%~M "%OUT%" >nul 2>&1 || (
            echo [!] HvEfi.efi is missing "%%~M" - the image is TRUNCATED.
            echo     A driver that silently loses part of its bring-up path does
            echo     not fail loudly; it presents as "the EFI broke the machine".
            echo     Check the /GL flag in HvEfi.inf before anything else.
            set "MISSING=1"
        )
    )
    findstr /c:"BOOT HIT" "%BOOTOUT%" >nul 2>&1 || (
        echo [!] HvBoot.efi is missing "BOOT HIT" - wrong or stale artifact.
        set "MISSING=1"
    )
    findstr /c:"FULL DONE" "%BOOTOUT%" >nul 2>&1 || (
        echo [!] HvBoot.efi is missing "FULL DONE" - pre-Pass-90 application.
        set "MISSING=1"
    )
)

rem ── Ticket sentinel check ────────────────────────────────────────────────
rem The launcher patches these two images by scanning their writable data
rem section for the two sentinel patterns. If a pattern and the compiled image
rem disagree, the launcher refuses the image and the machine sits at core
rem step 5 with no diagnostic - which is what a byte-order mistake in a
rem hand-copied GUID pattern looked like in practice.
rem
rem Both PAIRS are checked on purpose: the two build-tree outputs and the two
rem repo copies this script stages from them. A silent staging failure would
rem otherwise leave a stale, unpatchable image in the repo under a green build.
rem
rem check_sentinels.ps1 parses the expected bytes out of the single owner in
rem hv_launcher.c. In the standalone HvEfi repo, hv_launcher.c is not present,
rem so the sentinel check is skipped. When building from the full Hypervisor
rem repo, set HV_LAUNCHER_SRC to the launcher source path to enable it.
if "%MISSING%"=="0" (
    if defined HV_LAUNCHER_SRC (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%SRC%check_sentinels.ps1" -LauncherSource "%HV_LAUNCHER_SRC%" -Images "%OUT%;%BOOTOUT%;%SRC%HvEfi.efi;%SRC%HvBoot.efi"
        if errorlevel 1 (
            echo [!] Ticket sentinel check FAILED - see the diagnosis above.
            echo     The launcher would refuse these images as unpatchable.
            set "MISSING=1"
        )
    ) else (
        echo [*] Sentinel check skipped ^(set HV_LAUNCHER_SRC to enable^)
    )
)

rem ── Manifest ─────────────────────────────────────────────────────────────
rem One canonical record of what this build produced, in the repo. The
rem launcher checks a source binary against it before installing, so a stale
rem copy is refused instead of being written to the ESP.
if "%MISSING%"=="0" (
    echo # HvEfi build manifest - generated by HvEfi\build_hvefi.bat > "%SRC%build_manifest.txt"
    echo # columns: target  size  name  sha256 >> "%SRC%build_manifest.txt"
    powershell -NoProfile -Command "'%HV_BUILD_TARGET%  ' + (Get-Item '%OUT%').Length + '  HvEfi.efi  ' + (Get-FileHash -Algorithm SHA256 '%OUT%').Hash.ToLower()" >> "%SRC%build_manifest.txt"
    powershell -NoProfile -Command "'%HV_BUILD_TARGET%  ' + (Get-Item '%BOOTOUT%').Length + '  HvBoot.efi  ' + (Get-FileHash -Algorithm SHA256 '%BOOTOUT%').Hash.ToLower()" >> "%SRC%build_manifest.txt"
    echo [+] Manifest: %SRC%build_manifest.txt
)

if not "%MISSING%"=="0" exit /b 1
exit /b 0
