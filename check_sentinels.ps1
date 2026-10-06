<#
    check_sentinels.ps1 - assert the ticket patch sentinels are really present in
    the built EFI images.

    Why this exists
    ---------------
    The launcher patches two unprovisioned images (HvEfi.efi the core,
    HvBoot.efi the bridge) by scanning their writable-initialised data section
    for a fixed byte pattern and overwriting it. If that pattern is wrong, or
    the image stops containing it, the scan finds nothing and the launcher
    either refuses the image ("sentinels ambiguous") or, worse, silently skips
    it. Both look identical to "the ticket was never provisioned", and the
    machine then sits at core step 5 forever with no way to tell why.

    That is not hypothetical: a hand-copied copy of the GUID pattern had its
    Data3 bytes reversed (0xC0DE stored as C0 DE instead of DE C0), so
    --install-raw refused every HvBoot.efi it was given.

    So this compares the pattern the launcher will search for against the bytes
    actually compiled into each image, and fails the build if they disagree.
    The expected bytes are parsed out of the single owner in
    Hypervisor/hv_launcher.c, not hard-coded here - otherwise this file becomes
    a fourth copy and the same bug walks straight back in.

    Exit 0 = both images carry exactly one of each sentinel.
    Exit 1 = anything else.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$LauncherSource,
    # Semicolon-separated list rather than [string[]]: this script is called
    # from both a .bat and a .sh, and array binding across those two is the kind
    # of thing that silently checks one image instead of two.
    [Parameter(Mandatory = $true)][string]$Images
)

$ErrorActionPreference = 'Stop'

function Get-SentinelBytes {
    param([string]$Source, [string]$Name, [int]$ExpectedLength)

    $text = [System.IO.File]::ReadAllText($Source)
    # Match the array literal, comments and all.
    $m = [regex]::Match($text,
        "static\s+const\s+BYTE\s+$Name\s*\[\s*\]\s*=\s*\{(?<body>[^}]*)\}")
    if (-not $m.Success) {
        throw "check_sentinels: '$Name' not found in $Source. The single owner was renamed or removed; this gate must be updated with it."
    }
    $body = $m.Groups['body'].Value -replace '//[^\n]*', ''
    # Build the array explicitly: a pipeline result would unroll to a scalar
    # for a one-element match and then .ToArray() would not exist.
    [byte[]]$vals = @()
    foreach ($m in [regex]::Matches($body, '0x([0-9A-Fa-f]{2})')) {
        $vals += [Convert]::ToByte($m.Groups[1].Value, 16)
    }
    if ($vals.Count -ne $ExpectedLength) {
        throw "check_sentinels: '$Name' has $($vals.Count) bytes, expected $ExpectedLength."
    }
    return ,$vals
}

# Locate the writable-initialised data section: the same rule the launcher uses,
# because a check that searched the whole file could pass on a match inside
# .text and would not prove what the launcher's scan would find.
function Get-DataSectionRange {
    param([byte[]]$Image)

    if ($Image.Length -lt 64 -or $Image[0] -ne 0x4D -or $Image[1] -ne 0x5A) {
        throw 'check_sentinels: not a PE image (no MZ).'
    }
    $lfanew = [BitConverter]::ToInt32($Image, 0x3C)
    if ($lfanew -le 0 -or ($lfanew + 24) -gt $Image.Length) {
        throw 'check_sentinels: bogus e_lfanew.'
    }
    $numSections = [BitConverter]::ToUInt16($Image, $lfanew + 6)
    $optSize     = [BitConverter]::ToUInt16($Image, $lfanew + 20)
    $secOff      = $lfanew + 24 + $optSize

    for ($i = 0; $i -lt $numSections; $i++) {
        $s = $secOff + ($i * 40)
        if (($s + 40) -gt $Image.Length) { break }
        $chars = [BitConverter]::ToUInt32($Image, $s + 36)
        $cntInit = ($chars -band 0x40) -ne 0     # IMAGE_SCN_CNT_INITIALIZED_DATA
        $write   = ($chars -band 0x80000000) -ne 0
        if ($cntInit -and $write) {
            $rawOff  = [BitConverter]::ToUInt32($Image, $s + 20)
            $rawSize = [BitConverter]::ToUInt32($Image, $s + 16)
            if ($rawSize -gt 0 -and $rawOff -le ($Image.Length - $rawSize)) {
                return @($rawOff, $rawSize)
            }
        }
    }
    throw 'check_sentinels: no writable initialised data section found.'
}

function Count-Hits {
    param([byte[]]$Haystack, [int]$Off, [int]$Size, [byte[]]$Needle)

    $hits = 0
    $last = $Off + $Size - $Needle.Length
    for ($i = $Off; $i -le $last; $i++) {
        $match = $true
        for ($j = 0; $j -lt $Needle.Length; $j++) {
            if ($Haystack[$i + $j] -ne $Needle[$j]) { $match = $false; break }
        }
        if ($match) { $hits++ }
    }
    return $hits
}

try {
    $namePat = Get-SentinelBytes -Source $LauncherSource -Name 'gHvTicketNameSentinel' -ExpectedLength 10
    $guidPat = Get-SentinelBytes -Source $LauncherSource -Name 'gHvTicketGuidSentinel' -ExpectedLength 16
} catch {
    Write-Host "[!] $($_.Exception.Message)"
    exit 1
}

$guidHex = ($guidPat | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
Write-Host "  sentinel name: $(($namePat | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')"
Write-Host "  sentinel guid: $guidHex"

$failed = $false
$checked = 0
$imageList = $Images -split '[;,]'
foreach ($img in $imageList) {
    if ([string]::IsNullOrWhiteSpace($img)) { continue }
    $checked++
    if (-not (Test-Path -LiteralPath $img)) {
        Write-Host "[!] $([System.IO.Path]::GetFileName($img)): not found - cannot check sentinels."
        $failed = $true
        continue
    }
    $bytes = [System.IO.File]::ReadAllBytes($img)
    $label = [System.IO.Path]::GetFileName($img)
    try {
        $range = Get-DataSectionRange -Image $bytes
        $nHits = Count-Hits -Haystack $bytes -Off $range[0] -Size $range[1] -Needle $namePat
        $gHits = Count-Hits -Haystack $bytes -Off $range[0] -Size $range[1] -Needle $guidPat
    } catch {
        Write-Host "[!] ${label}: $($_.Exception.Message)"
        $failed = $true
        continue
    }

    if ($nHits -ne 1 -or $gHits -ne 1) {
        $why = if ($nHits -eq 0 -and $gHits -eq 0) {
            'no sentinels at all - either the image was built from a binary that no longer declares them, or you are checking an already-provisioned image'
        } elseif ($nHits -eq 0) { 'the variable-name sentinel is absent; the launcher cannot find the field' }
        elseif ($gHits -eq 0) { 'the GUID sentinel is absent - the launcher will refuse this image as unpatchable' }
        else { 'more than one hit - the launcher refuses an ambiguous image rather than patch the wrong offset' }
        Write-Host "[!] ${label}: name x$nHits, guid x$gHits. $why."
        Write-Host "    Expected name: $(($namePat | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')"
        Write-Host "    Expected guid: $guidHex"
        Write-Host '    If the pattern itself is wrong, fix the single owner in Hypervisor\hv_launcher.c'
        Write-Host '    (gHvTicketGuidSentinel / gHvTicketNameSentinel) - do not patch a copy.'
        $failed = $true
    } else {
        Write-Host "  ok    ${label}: 1 name + 1 guid sentinel in .data (name x$nHits, guid x$gHits)"
    }
}

# A list that names no image at all must not report success: the caller would
# read exit 0 as "the images were verified" when nothing was opened.
if ($checked -eq 0) {
    Write-Host '[!] check_sentinels: no images to check (the -Images list was empty or all whitespace).'
    exit 1
}

if ($failed) { exit 1 }
exit 0