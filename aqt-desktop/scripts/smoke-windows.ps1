# Smoke test of the Windows installer, for the CI runner: it installs the app for the current user, opens the
# app window (--smoke) and uninstalls it again, so do not run it on a PC someone is working on.
#
#  1. silent per-user install (NSIS /S), found through its uninstall entry under HKCU;
#  2. the folder of aqt.exe is on the user's PATH, and a new terminal finds aqt there: --version, status, setup --help;
#  3. Claude Code hook commands through Git Bash, as Claude Code on Windows runs them (UTF-8 text on stdin; with no
#     writer the trail hook spools its record);
#  4. the app's --smoke run (core ready, one request, the page's first answer), -Runs times in the same folders;
#  5. silent uninstall: the uninstall entry, aqt.exe and the PATH entry are gone.
# AQT's own folders are throw-away (XDG_CONFIG_HOME and XDG_STATE_HOME, which AQT honours on Windows too).
#
# Usage: pwsh aqt-desktop/scripts/smoke-windows.ps1 -Installer aqt-desktop\dist\aqt-desktop_<version>_x64-setup.exe [-Runs 2]
param([Parameter(Mandatory = $true)] [string] $Installer, [int] $Runs = 1)
$ErrorActionPreference = 'Stop'

$work = Join-Path ([IO.Path]::GetTempPath()) ('aqt-smoke-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
foreach ($sub in 'config', 'state') { New-Item -ItemType Directory -Force -Path (Join-Path $work $sub) | Out-Null }
$env:XDG_CONFIG_HOME = Join-Path $work 'config'
$env:XDG_STATE_HOME = Join-Path $work 'state'
Remove-Item Env:PYTHONPATH, Env:PYTHONHOME, Env:PYTHONUTF8 -ErrorAction SilentlyContinue   # as on a user's PC

function Get-UserPath {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment')
    [string]$key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
}
function Test-OnUserPath([string] $folder) {
    [bool]((Get-UserPath) -split ';' | Where-Object { $_ -and $_.TrimEnd('\') -eq $folder })
}
function Get-UninstallEntry {
    Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall' | Get-ItemProperty |
        Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -like 'Agent Quality Toolkit*' } |
        Select-Object -First 1
}
function Invoke-Checked([string] $what, [scriptblock] $block, [int[]] $ok = @(0)) {
    & $block
    if ($ok -notcontains $LASTEXITCODE) { throw "$what failed (exit $LASTEXITCODE)" }
}

# 1. install for this user only
$setup = Start-Process -FilePath (Resolve-Path $Installer).Path -ArgumentList '/S' -Wait -PassThru
if ($setup.ExitCode -ne 0) { throw "installer exit code $($setup.ExitCode)" }
$entry = Get-UninstallEntry
if (-not $entry) { throw 'no uninstall entry under HKCU: the app was not installed for the current user' }
$uninstaller = $entry.UninstallString.Trim('"')
$dir = Split-Path $uninstaller
$runtime = Join-Path $dir 'runtime\aqt'
Write-Host "installed per user in $dir"

# 2. aqt on the user's PATH, as a new terminal sees it
if (-not (Test-OnUserPath $runtime)) { throw "$runtime is not on the user's PATH: $(Get-UserPath)" }
$env:Path = "$runtime;$env:Path"
$found = (Get-Command aqt).Source
if ($found -ne (Join-Path $runtime 'aqt.exe')) { throw "aqt resolves to $found" }
Invoke-Checked 'aqt --version' { aqt --version }
$status = Join-Path $work 'status.json'
Invoke-Checked 'aqt status --json' { aqt status --json > $status } @(0, 1)
$report = Get-Content $status -Raw | ConvertFrom-Json
Write-Host "aqt status: $($report.verdict) ($(@($report.checks).Count) checks)"
Invoke-Checked 'aqt setup --help' { aqt setup --help | Out-Null }

# 3. hook commands through Git Bash, with non-ASCII text in the hook's JSON
$bash = Join-Path $env:ProgramFiles 'Git\bin\bash.exe'
$hook = Join-Path $work 'hook.json'
[IO.File]::WriteAllText($hook, '{"hook_event_name":"UserPromptSubmit","session_id":"smoke","cwd":"C:/x","prompt":"Prüfung äöü"}',
                        (New-Object Text.UTF8Encoding $false))
$hookPath = $hook.Replace('\', '/')
foreach ($command in 'aqt trail hook claude-code', 'aqt change hook claude-code') {
    Invoke-Checked "Git Bash: $command" { & $bash -c "$command < '$hookPath'" }
}
$spool = Join-Path $env:XDG_STATE_HOME 'aqt\spool\spool.jsonl'
$line = [IO.File]::ReadAllText($spool, [Text.Encoding]::UTF8)
if ($line -notmatch 'Prüfung äöü') { throw "the trail hook did not spool the prompt as UTF-8: $line" }
Write-Host 'Git Bash hooks: ok (the trail hook spooled its record with the UTF-8 prompt)'

# 4. the app window
$app = Join-Path $dir 'aqt-desktop.exe'
for ($run = 1; $run -le $Runs; $run++) {
    $out = Join-Path $work "smoke-$run.out"
    $err = Join-Path $work "smoke-$run.err"
    $smoke = Start-Process -FilePath $app -ArgumentList '--smoke' -RedirectStandardOutput $out -RedirectStandardError $err -Wait -PassThru
    Get-Content $out | Where-Object { $_ -like '{"*' }
    if ($smoke.ExitCode -ne 0) { Get-Content $err -Tail 20; throw "smoke run $run failed (exit $($smoke.ExitCode))" }
}

# 5. uninstall; NSIS uninstallers continue from a copy in TEMP, so wait for the result
Start-Process -FilePath $uninstaller -ArgumentList '/S' -Wait | Out-Null
$deadline = (Get-Date).AddSeconds(120)
while (((Get-UninstallEntry) -or (Test-OnUserPath $runtime) -or (Test-Path (Join-Path $runtime 'aqt.exe'))) -and
       (Get-Date) -lt $deadline) { Start-Sleep -Seconds 1 }
if (Get-UninstallEntry) { throw 'the uninstall entry is still there' }
if (Test-OnUserPath $runtime) { throw "the PATH entry $runtime is still there" }
if (Test-Path (Join-Path $runtime 'aqt.exe')) { throw "$runtime\aqt.exe is still there" }
Write-Host 'uninstalled: the app, aqt.exe and the PATH entry are gone'
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
