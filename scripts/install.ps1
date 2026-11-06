# SPDX-License-Identifier: MIT
<#
.SYNOPSIS
Install or update kalkan as a Claude Code plugin with one command (Windows).

.DESCRIPTION
The script does these steps. Run it again at any time: every step checks what is there first.
  1. Check git (Git for Windows: the plugin runs its setup and hook in Git Bash), Python 3.11 or
     later and the Claude Code CLI (signed in), and that git can read the repository.
  2. Add the kalkan marketplace (claude plugin marketplace add dtechcloud/kalkan), or update
     it when it is there (claude plugin marketplace update kalkan).
  3. Install the plugin for your user (claude plugin install kalkan@kalkan --scope user), or
     update it (claude plugin update kalkan@kalkan).
  4. Run the plugin setup kalkan-setup in Git Bash: the engine venv, the pinned scanners, the
     local vulnerability databases and kalkan doctor (5 to 15 minutes the first time).
  5. Print the command that audits a project.
The exit code is 0 when everything worked and 1 when a check or a step failed; the message names
the fix. Works with Windows PowerShell 5.1 and PowerShell 7. Linux and macOS use install.sh.

.PARAMETER DryRun
Run only the checks. Print every command that would change something.

.PARAMETER Source
The marketplace source (default: dtechcloud/kalkan; also a local path or another GitHub
source that Claude Code accepts).

.PARAMETER SkipSetup
Leave out kalkan-setup (the next /kalkan in Claude Code runs it).

.EXAMPLE
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/dtechcloud/kalkan/main/scripts/install.ps1)))

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install.ps1 -DryRun
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [string]$Source = 'dtechcloud/kalkan',
    [switch]$SkipSetup
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Marketplace = 'kalkan'
$Plugin = 'kalkan@kalkan'
$DataId = 'kalkan-kalkan'
$VersionCheck = 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message"
}

function Write-Note {
    param([string]$Message)
    Write-Host "    $Message"
}

function Stop-Install {
    # The caller catches the error, prints the message and returns exit code 1.
    param([string]$Message)
    throw "kalkan install: error: $Message"
}

function Get-Program {
    # Return the path of a program on PATH, or $null.
    param([string]$Name)
    $found = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $found) {
        return $null
    }
    return $found.Path
}

function Invoke-Native {
    # Run a native command and return its stdout as one string ($LASTEXITCODE keeps the code).
    param([string]$Exe, [string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    $output = & $Exe @Arguments 2>$null
    return ($output | Out-String)
}

function Invoke-Change {
    # Run a command that changes something. A dry run prints it instead.
    param([string]$Exe, [string[]]$Arguments, [string]$Fix)
    $line = (@($Exe) + $Arguments) -join ' '
    if ($DryRun) {
        Write-Host "dry run: would run: $line"
        return
    }
    $ErrorActionPreference = 'Continue'
    & $Exe @Arguments
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Stop-Install "$line failed with exit code $code. $Fix"
    }
}

function Get-Field {
    # Return a property of a JSON object, or $null (Set-StrictMode refuses a missing property).
    param($Object, [string]$Name)
    if ($null -eq $Object) {
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function ConvertFrom-JsonText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }
    try {
        return ($Text | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Test-Python {
    # Return $true when the command runs Python 3.11 or later.
    param([string]$Exe, [string[]]$Prefix)
    $ErrorActionPreference = 'Continue'
    if ($null -eq (Get-Program $Exe)) {
        return $false
    }
    try {
        & $Exe @Prefix -c $VersionCheck *> $null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Find-Sh {
    # Return the sh.exe of Git for Windows: on PATH, else next to git.exe.
    $sh = Get-Program 'sh'
    if ($null -ne $sh) {
        return $sh
    }
    $git = Get-Program 'git'
    if ($null -eq $git) {
        return $null
    }
    $root = Split-Path -Parent (Split-Path -Parent $git)
    foreach ($relative in @('bin\sh.exe', 'usr\bin\sh.exe')) {
        $candidate = Join-Path $root $relative
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    return $null
}

function Test-GitAccess {
    # Return $true when git can read the repository (https first, then ssh), without a prompt.
    param([string]$Repository)
    $saved = @{ prompt = $env:GIT_TERMINAL_PROMPT; ssh = $env:GIT_SSH_COMMAND }
    try {
        $env:GIT_TERMINAL_PROMPT = '0'
        $null = Invoke-Native 'git' @('ls-remote', '--exit-code', "https://github.com/$Repository.git", 'HEAD')
        if ($LASTEXITCODE -eq 0) {
            return $true
        }
        $env:GIT_SSH_COMMAND = 'ssh -o BatchMode=yes'
        $null = Invoke-Native 'git' @('ls-remote', '--exit-code', "git@github.com:$Repository.git", 'HEAD')
        return ($LASTEXITCODE -eq 0)
    } finally {
        $env:GIT_TERMINAL_PROMPT = $saved.prompt
        $env:GIT_SSH_COMMAND = $saved.ssh
    }
}

function Test-Listed {
    # Return $true when a JSON list of objects has an item whose field equals the value.
    param($Items, [string]$Field, [string]$Value)
    foreach ($item in @($Items)) {
        if ((Get-Field $item $Field) -eq $Value) {
            return $true
        }
    }
    return $false
}

function Get-InstallPath {
    # Return the install folder of the plugin (the user scope first), or $null.
    param($Items)
    $found = $null
    foreach ($item in @($Items)) {
        if ((Get-Field $item 'id') -ne $Plugin) {
            continue
        }
        $path = Get-Field $item 'installPath'
        if ([string]::IsNullOrEmpty($path)) {
            continue
        }
        if ((Get-Field $item 'scope') -eq 'user') {
            return $path
        }
        if ($null -eq $found) {
            $found = $path
        }
    }
    return $found
}

function Invoke-Install {
    # 1. Checks
    Write-Step 'Check git'
    $git = Get-Program 'git'
    if ($null -eq $git) {
        Stop-Install 'git is not installed. Install Git for Windows (https://git-scm.com/download/win), then run this installer again.'
    }
    Write-Note (Invoke-Native 'git' @('--version')).Trim()

    Write-Step 'Check Python 3.11 or later'
    $python = $null
    foreach ($candidate in @(@{ Exe = 'py'; Prefix = @('-3') }, @{ Exe = 'python'; Prefix = @() }, @{ Exe = 'python3'; Prefix = @() })) {
        if (Test-Python -Exe $candidate.Exe -Prefix $candidate.Prefix) {
            $python = $candidate
            break
        }
    }
    if ($null -eq $python) {
        Stop-Install 'Python 3.11 or later was not found. Install it (https://www.python.org/downloads/), then run this installer again.'
    }
    $prefix = @($python.Prefix)
    Write-Note (Invoke-Native $python.Exe ($prefix + @('--version'))).Trim()

    Write-Step 'Check the Claude Code CLI'
    if ($null -eq (Get-Program 'claude')) {
        Stop-Install 'the Claude Code CLI (claude) is not on PATH. Install Claude Code, sign in with: claude auth login, then run this installer again.'
    }
    $version = (Invoke-Native 'claude' @('--version')).Trim()
    Write-Note (($version -split "`n")[0]).Trim()
    $auth = ConvertFrom-JsonText (Invoke-Native 'claude' @('auth', 'status', '--json'))
    $loggedIn = Get-Field $auth 'loggedIn'
    if ($loggedIn -eq $true) {
        Write-Note 'signed in'
    } elseif ($loggedIn -eq $false) {
        Stop-Install 'Claude Code is not signed in. Run: claude auth login. Then run this installer again.'
    } else {
        [Console]::Error.WriteLine('kalkan install: warning: cannot read the login state (claude auth status). If Claude Code asks you to sign in later, run: claude auth login')
    }
    $config = Get-Field $auth 'configDirectory'
    if ([string]::IsNullOrEmpty($config)) {
        $config = $env:CLAUDE_CONFIG_DIR
    }
    if ([string]::IsNullOrEmpty($config)) {
        $config = Join-Path $HOME '.claude'
    }
    # CLAUDE_CODE_PLUGIN_CACHE_DIR moves the plugins root (cache, marketplaces and data) of Claude Code.
    $pluginsRoot = $env:CLAUDE_CODE_PLUGIN_CACHE_DIR
    if ([string]::IsNullOrEmpty($pluginsRoot)) {
        $pluginsRoot = Join-Path $config 'plugins'
    }
    $data = Join-Path (Join-Path $pluginsRoot 'data') $DataId
    $dataForward = $data.Replace('\', '/')

    $githubRepo = $null
    if ($Source -match '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+([#@].+)?$' -and -not (Test-Path -LiteralPath $Source)) {
        $githubRepo = ($Source -split '[#@]')[0]
    }
    if ($null -ne $githubRepo) {
        Write-Step 'Check that git can read the kalkan repository'
        if (-not (Test-GitAccess $githubRepo)) {
            Stop-Install "git cannot read https://github.com/$githubRepo.git. When the repository needs a GitHub login, run: gh auth login, then gh auth setup-git. Then run this installer again."
        }
        Write-Note "git can read $githubRepo"
    }

    $sh = Find-Sh
    if ($null -eq $sh -and -not $SkipSetup) {
        Stop-Install 'cannot find sh.exe of Git for Windows (the plugin setup and hook run in Git Bash). Install Git for Windows (https://git-scm.com/download/win), then run this installer again.'
    }

    # 2. Marketplace and plugin
    Write-Step 'Add or update the kalkan marketplace'
    $markets = ConvertFrom-JsonText (Invoke-Native 'claude' @('plugin', 'marketplace', 'list', '--json'))
    if (Test-Listed $markets 'name' $Marketplace) {
        Invoke-Change 'claude' @('plugin', 'marketplace', 'update', $Marketplace) 'Run this installer again.'
    } else {
        Invoke-Change 'claude' @('plugin', 'marketplace', 'add', $Source) 'When the repository needs a GitHub login, run: gh auth setup-git. Then run this installer again.'
    }

    Write-Step 'Install or update the kalkan plugin (user scope)'
    $plugins = ConvertFrom-JsonText (Invoke-Native 'claude' @('plugin', 'list', '--json'))
    if (Test-Listed $plugins 'id' $Plugin) {
        Invoke-Change 'claude' @('plugin', 'update', $Plugin) 'Run this installer again.'
    } else {
        Invoke-Change 'claude' @('plugin', 'install', $Plugin, '--scope', 'user') 'Run this installer again.'
    }

    # 3. Setup: engine, scanners, databases, doctor
    Write-Step 'Set up the engine, the pinned scanners and the vulnerability databases (kalkan-setup)'
    $plugins = ConvertFrom-JsonText (Invoke-Native 'claude' @('plugin', 'list', '--json'))
    $root = Get-InstallPath $plugins
    if ($SkipSetup) {
        Write-Note 'skipped (-SkipSetup): the next /kalkan in Claude Code runs it'
    } elseif ($null -eq $root) {
        if ($DryRun) {
            Write-Host "dry run: would run: $sh <plugin folder>/bin/kalkan-setup $dataForward"
        } else {
            Stop-Install 'cannot find the installed kalkan plugin (claude plugin list --json). Run this installer again.'
        }
    } else {
        $setup = Join-Path (Join-Path $root 'bin') 'kalkan-setup'
        if (-not $DryRun -and -not (Test-Path -LiteralPath $setup -PathType Leaf)) {
            Stop-Install "the plugin folder $root has no bin\kalkan-setup. Update the plugin: claude plugin update $Plugin"
        }
        Write-Note 'this takes 5 to 15 minutes the first time and about 2 seconds later'
        Invoke-Change $sh @($setup.Replace('\', '/'), $dataForward) 'Run this installer again; installed tools are kept.'
    }

    # 4. The audit command
    $launcher = Join-Path (Join-Path $data 'bin') 'kalkan-audit.cmd'
    Write-Step 'Done. Audit a project with one command:'
    Write-Note "PowerShell: & `"$launcher`" <folder or git URL>"
    Write-Note "cmd:        `"$launcher`" <folder or git URL>"
    Write-Note "Git Bash:   sh `"$dataForward/bin/kalkan-audit`" <folder or git URL>"
    Write-Note 'Options: --profile fast|standard|deep, --tools-only (no Claude Code), --open, --yes'
    Write-Note "Resume a stopped audit: & `"$launcher`" devam <run-id>"
    Write-Note 'Reports: ~\kalkan-runs\<run-id>\report\. Restart Claude Code to use /kalkan in a session.'
}

# A script file ends with its exit code. The one-line form (a script block) sets $LASTEXITCODE
# and returns, so it never closes the PowerShell window.
$installCode = 0
try {
    Invoke-Install
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    $installCode = 1
}
if ($PSCommandPath) {
    exit $installCode
}
$global:LASTEXITCODE = $installCode
