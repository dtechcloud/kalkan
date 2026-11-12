# SPDX-License-Identifier: MIT
<#
.SYNOPSIS
Set up kalkan on Windows.

.DESCRIPTION
The script does these steps in the repository root:
  1. Find Python 3.11 or later (py launcher, python, python3).
  2. Create .venv when it is missing.
  3. Install kalkan into .venv: pip install -e .
  4. Install every pinned tool, the Go toolchain included: kalkan tools install --all
  5. Download the local vulnerability databases: kalkan sca update-db --max-age 168 (a
     database younger than 7 days, the stale limit of kalkan doctor, is kept; a failure only
     warns: sca match then records a database gap; it never queries an online API)
  6. Check the environment: kalkan doctor
Steps 1 to 3 stop the script at the first failure. Step 6 also runs after a failed step 4, so
that the doctor table shows what is missing. The exit code is 1 when step 4 failed or when the
doctor reports a fail (a manifest tool missing or broken). Docker and git are warnings only.
Works with Windows PowerShell 5.1 and PowerShell 7.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\bootstrap.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$VenvDir = Join-Path $RepoRoot '.venv'
$VenvPython = Join-Path (Join-Path $VenvDir 'Scripts') 'python.exe'
$VersionCheck = 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message"
}

function Stop-Bootstrap {
    param([string]$Message)
    Write-Host "bootstrap: error: $Message" -ForegroundColor Red
    exit 1
}

function Test-Python {
    # Return $true when the command runs Python 3.11 or later.
    param([string]$Exe, [string[]]$Prefix)
    $ErrorActionPreference = 'Continue'
    if (-not (Get-Command $Exe -CommandType Application -ErrorAction SilentlyContinue)) {
        return $false
    }
    try {
        & $Exe @Prefix -c $VersionCheck *> $null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Find-Python {
    # Return the command (an array: executable, then prefix arguments) of a usable Python.
    $candidates = @(
        @{ Exe = 'py'; Prefix = @('-3') },
        @{ Exe = 'python'; Prefix = @() },
        @{ Exe = 'python3'; Prefix = @() }
    )
    foreach ($candidate in $candidates) {
        if (Test-Python -Exe $candidate.Exe -Prefix $candidate.Prefix) {
            return , (@($candidate.Exe) + $candidate.Prefix)
        }
    }
    return $null
}

function Invoke-Step {
    # Run a native command, show it, and stop when it fails.
    param([string]$Description, [string]$Exe, [string[]]$Arguments)
    Write-Step $Description
    $ErrorActionPreference = 'Continue'
    & $Exe @Arguments
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Stop-Bootstrap "$Description failed with exit code $code."
    }
}

function Invoke-Check {
    # Run a native command, show its output, and return its exit code (the script goes on).
    param([string]$Description, [string]$Exe, [string[]]$Arguments)
    Write-Step $Description
    $ErrorActionPreference = 'Continue'
    & $Exe @Arguments | Out-Host
    return $LASTEXITCODE
}

if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
    $python = Find-Python
    if ($null -eq $python) {
        Stop-Bootstrap 'Python 3.11 or later was not found. Install it from https://www.python.org and run this script again.'
    }
    $exe = $python[0]
    $prefix = @($python | Select-Object -Skip 1)
    Invoke-Step -Description 'Create .venv' -Exe $exe -Arguments ($prefix + @('-m', 'venv', $VenvDir))
    if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
        Stop-Bootstrap "python -m venv did not create $VenvPython."
    }
} else {
    Write-Step "Use the existing .venv ($VenvPython)"
}

if (-not (Test-Python -Exe $VenvPython -Prefix @())) {
    Stop-Bootstrap '.venv does not run Python 3.11 or later. Remove .venv and run this script again.'
}

Invoke-Step -Description 'Install kalkan into .venv (pip install -e .)' -Exe $VenvPython `
    -Arguments @('-m', 'pip', 'install', '--disable-pip-version-check', '--no-cache-dir', '-e', $RepoRoot)
$installCode = Invoke-Check -Description 'Install every pinned tool, Go included (kalkan tools install --all)' `
    -Exe $VenvPython -Arguments @('-m', 'kalkan', 'tools', 'install', '--all')
$dbCode = Invoke-Check -Description 'Download the local vulnerability databases (kalkan sca update-db --max-age 168)' `
    -Exe $VenvPython -Arguments @('-m', 'kalkan', 'sca', 'update-db', '--max-age', '168')
if ($dbCode -ne 0) {
    Write-Warning "kalkan sca update-db failed (exit code $dbCode); sca match records a database gap until it works. Run: $VenvPython -m kalkan sca update-db"
}
$doctorCode = Invoke-Check -Description 'Check the environment (kalkan doctor)' -Exe $VenvPython `
    -Arguments @('-m', 'kalkan', 'doctor')

if ($installCode -ne 0) {
    Stop-Bootstrap "kalkan tools install --all failed with exit code $installCode. Read the table above, fix the cause and run this script again."
}
if ($doctorCode -ne 0) {
    Stop-Bootstrap "kalkan doctor reported a fail (exit code $doctorCode). Run the command in the DETAIL column of each fail row, then run this script again."
}

Write-Step 'Done. Activate the venv with: .venv\Scripts\Activate.ps1'
exit 0
