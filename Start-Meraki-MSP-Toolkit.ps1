$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Here

$LogDir = Join-Path $Here 'Logs'
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$LauncherLog = Join-Path $LogDir 'Launcher.log'

function Write-LauncherLog {
    param([string]$Message)
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $LauncherLog -Value "[$stamp] $Message" -Encoding UTF8
}

try {
    $script = Join-Path $Here 'Meraki-MSP-Toolkit.py'
    if (-not (Test-Path $script)) {
        throw "Meraki-MSP-Toolkit.py was not found in $Here"
    }

    try { Unblock-File -Path $script -ErrorAction SilentlyContinue } catch {}

    $command = $null
    $arguments = @()
    $hideConsole = $false

    $pyw = Get-Command pyw.exe -ErrorAction SilentlyContinue
    if ($pyw) {
        $command = $pyw.Source
        $arguments = @('-3', $script)
    }
    else {
        $pythonw = Get-Command pythonw.exe -ErrorAction SilentlyContinue
        if ($pythonw) {
            $command = $pythonw.Source
            $arguments = @($script)
        }
        else {
            $py = Get-Command py.exe -ErrorAction SilentlyContinue
            if ($py) {
                $command = $py.Source
                $arguments = @('-3', $script)
                $hideConsole = $true
            }
            else {
                $python = Get-Command python.exe -ErrorAction SilentlyContinue
                if ($python) {
                    $command = $python.Source
                    $arguments = @($script)
                    $hideConsole = $true
                }
                else {
                    throw 'Python 3 was not found. Install Python 3 or make py/python available in PATH.'
                }
            }
        }
    }

    $startArgs = @{
        FilePath         = $command
        ArgumentList     = $arguments
        WorkingDirectory = $Here
        PassThru         = $true
    }
    if ($hideConsole) {
        $startArgs.WindowStyle = 'Hidden'
    }

    $proc = Start-Process @startArgs
    Write-LauncherLog "Started Meraki MSP Toolkit v0.2.0 (PID $($proc.Id)) using $command"
}
catch {
    $msg = $_.Exception.Message
    Write-LauncherLog "LAUNCH FAILED: $msg"
    try {
        Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
        [System.Windows.MessageBox]::Show(
            "Meraki MSP Toolkit could not start.`n`n$msg`n`nSee:`n$LauncherLog",
            'Meraki MSP Toolkit',
            'OK',
            'Error'
        ) | Out-Null
    }
    catch {}
    exit 1
}
