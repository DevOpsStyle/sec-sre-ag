<#
.SYNOPSIS
Builds the portable setup wizard: the target computer needs neither Python nor Azure CLI.

.DESCRIPTION
Creates a virtual environment under build\wizard, installs the pinned build requirements,
records the plugin repository and commit in build-info.json, and packages
tools\wizard\sre_setup_wizard.py with PyInstaller, together with wizard.html, the skills
(used to detect name conflicts) and docs\known-issues.md. It produces:

  dist\SRE-Agent-Setup.exe          single file: double-click it
  dist\SRE-Agent-Setup-folder.zip   same wizard as a folder, for computers whose security policy
                                    blocks programs that unpack themselves into the Temp folder

.PARAMETER Repo
GitHub repository (owner/name) that the wizard installs as a plugin by default.
Default: the `origin` remote of this clone.

.PARAMETER Python
Python 3.10+ interpreter used to create the build environment.

.EXAMPLE
pwsh tools/wizard/build.ps1
pwsh tools/wizard/build.ps1 -Repo contoso/sec-sre-ag
#>
param(
    [string]$Repo = "",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$work = Join-Path $root "build\wizard"
$dist = Join-Path $root "dist"
$venv = Join-Path $work "venv"
$py = Join-Path $venv "Scripts\python.exe"
$name = "SRE-Agent-Setup"
New-Item -ItemType Directory -Force -Path $work, $dist | Out-Null

if (-not (Test-Path $py)) {
    & $Python -m venv $venv
    if ($LASTEXITCODE) { throw "Cannot create the virtual environment with '$Python'." }
}
& $py -m pip install --disable-pip-version-check --quiet -r (Join-Path $PSScriptRoot "requirements-build.txt")
if ($LASTEXITCODE) { throw "pip install failed." }

if (-not $Repo) {
    $remote = git -C $root remote get-url origin 2>$null
    if ($remote -match 'github\.com[:/]+([^/]+)/([^/]+?)(\.git)?/?$') { $Repo = "$($Matches[1])/$($Matches[2])" }
}
if (-not $Repo) { Write-Warning "No plugin repository detected: the user must type it in the wizard (Advanced options)." }
$commit = git -C $root rev-parse --short HEAD 2>$null
$info = [ordered]@{ repo = $Repo; commit = "$commit"; built = (Get-Date -Format "yyyy-MM-dd") }
$info | ConvertTo-Json | Set-Content -Path (Join-Path $work "build-info.json") -Encoding utf8

function Invoke-PyInstaller([string]$Mode, [string]$DistPath) {
    $sep = [IO.Path]::PathSeparator  # PyInstaller SOURCE<sep>DEST, ';' on Windows
    & $py -m PyInstaller --noconfirm --clean "--$Mode" --console --name $name `
        --distpath $DistPath `
        --workpath (Join-Path $work "pyinstaller-$Mode") `
        --specpath $work `
        --paths (Join-Path $root "tools") `
        --add-data "$(Join-Path $PSScriptRoot 'wizard.html')$sep." `
        --add-data "$(Join-Path $work 'build-info.json')$sep." `
        --add-data "$(Join-Path $root 'skills')${sep}skills" `
        --add-data "$(Join-Path $root 'docs\known-issues.md')${sep}docs" `
        (Join-Path $PSScriptRoot "sre_setup_wizard.py")
    if ($LASTEXITCODE) { throw "PyInstaller ($Mode) failed." }
}

Invoke-PyInstaller "onefile" $dist

$folder = Join-Path $work "onedir"
Invoke-PyInstaller "onedir" $folder
$zip = Join-Path $dist "$name-folder.zip"
Compress-Archive -Path (Join-Path $folder $name) -DestinationPath $zip -Force

foreach ($file in @((Join-Path $dist "$name.exe"), $zip)) {
    Write-Host ("Built {0} ({1} MB)" -f $file, [math]::Round((Get-Item $file).Length / 1MB, 1))
}
Write-Host "Default plugin repository: '$Repo', commit $commit"
