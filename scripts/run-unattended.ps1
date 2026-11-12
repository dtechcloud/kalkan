# SPDX-License-Identifier: MIT
<#
.SYNOPSIS
Run or resume a kalkan audit unattended (headless) on Windows.

.DESCRIPTION
The script calls <repository root>\.venv\Scripts\kalkan.exe unattended with all its arguments
and passes the exit code through. kalkan unattended starts Claude Code headless in rounds from
the repository root, waits through usage-limit resets, and stops when the audit is done (exit
code 0), incomplete (exit code 1) or after --max-hours (exit code 1).
A relative target path is relative to your current folder.
Works with Windows PowerShell 5.1 and PowerShell 7.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run-unattended.ps1 C:\code\app --profile deep

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run-unattended.ps1 devam
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Kalkan = Join-Path (Join-Path (Join-Path $RepoRoot '.venv') 'Scripts') 'kalkan.exe'
$Arguments = @($args)

$Usage = @'
Usage: scripts\run-unattended.ps1 <target | devam [RUN_ID]> [options]

Run or resume a kalkan audit headless. The script waits through usage-limit resets.

  <target>               local folder or git URL to audit (creates a new run)
  devam RUN_ID           resume this run
  devam                  resume the run in runs\LATEST
  --run RUN_ID           with devam: the run to resume
  --profile NAME         fast, standard (default) or deep
  --no-latest            new run only: keep runs\LATEST unchanged
  --max-hours N          stop after N hours in total (default: 24)
  --round-hours N        stop one host round after N hours (default: 6)
  --host NAME            claude (default) or codex
  --log-dir DIR          folder of the log file (default: runs)
  --dry-run              print the command lines and start nothing
  --json                 print the result as JSON
  -h, --help             show this text

All options: .venv\Scripts\kalkan.exe unattended --help
'@

if ($Arguments.Count -eq 0) {
    [Console]::Error.WriteLine($Usage)
    exit 2
}
foreach ($Argument in $Arguments) {
    if ($Argument -in @('-h', '--help', '-?', '/?')) {
        Write-Output $Usage
        exit 0
    }
}

if (-not (Test-Path -LiteralPath $Kalkan -PathType Leaf)) {
    [Console]::Error.WriteLine("run-unattended: error: $Kalkan was not found. Set up kalkan first: powershell -NoProfile -ExecutionPolicy Bypass -File scripts\bootstrap.ps1")
    exit 1
}

$ErrorActionPreference = 'Continue'
& $Kalkan unattended @Arguments
exit $LASTEXITCODE
