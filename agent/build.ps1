<#
  Builds the Asset Inventory Agent:
    dist\AssetAgent\            installed program (Windows service host, onedir = reliable for services)
    dist\AssetAgentSetup.exe    single-file setup wizard containing the program (published to the portal)

  Usage:  powershell -ExecutionPolicy Bypass -File build.ps1 [-CertThumbprint <code-signing cert>] [-TimestampUrl <url>]
  Signing is optional but strongly recommended for enterprise rollout (avoids SmartScreen "Unknown publisher").
#>
param([string]$CertThumbprint, [string]$TimestampUrl = 'http://timestamp.digicert.com')
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$venv = Join-Path $PSScriptRoot '.venv'
$py = "$venv\Scripts\python.exe"
if (-not (Test-Path $py)) { Write-Host 'Creating build virtualenv...'; python -m venv $venv }
& $py -m pip install --quiet --upgrade pip
& $py -m pip install --quiet pyinstaller pywin32 cryptography pillow
if ($LASTEXITCODE -ne 0) { throw 'pip install failed' }

$version = (Select-String -Path common.py -Pattern '^AGENT_VERSION = "(.+)"').Matches[0].Groups[1].Value
Write-Host "Building Asset Inventory Agent $version" -ForegroundColor Cyan
& $py make_assets.py

# ---- Windows version resources (shown in file Properties > Details)
$v4 = ($version.Split('.') + @('0', '0', '0'))[0..3] -join ', '
function New-VersionFile($path, $desc, $orig) {
@"
VSVersionInfo(
  ffi=FixedFileInfo(filevers=($v4), prodvers=($v4), mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'IT Asset Management'),
      StringStruct('FileDescription', '$desc'),
      StringStruct('FileVersion', '$version'),
      StringStruct('InternalName', '$orig'),
      StringStruct('LegalCopyright', 'Copyright (c) $((Get-Date).Year)'),
      StringStruct('OriginalFilename', '$orig'),
      StringStruct('ProductName', 'Asset Inventory Agent'),
      StringStruct('ProductVersion', '$version')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"@ | Set-Content -Encoding utf8 $path
}
New-Item -ItemType Directory -Force build | Out-Null
New-VersionFile build\ver_agent.txt 'Asset Inventory Agent' 'AssetAgent.exe'
New-VersionFile build\ver_setup.txt 'Asset Inventory Agent Setup' 'AssetAgentSetup.exe'

$hidden = @('win32timezone', 'win32ts', 'win32profile', 'win32process', 'win32security', 'win32api', 'win32con', 'win32gui', 'win32crypt', 'PIL', 'PIL.ImageGrab') | ForEach-Object { '--hidden-import', $_ }
$common = @('--noconfirm', '--clean', '--windowed', '--icon', "$PSScriptRoot\assets\icon.ico",
  '--add-data', "$PSScriptRoot\assets;assets") + $hidden + @('--distpath', 'dist', '--workpath', 'build\work', '--specpath', 'build')

# ---- 1. installed program (onedir)
& $py -m PyInstaller @common --onedir --name AssetAgent --version-file "$PSScriptRoot\build\ver_agent.txt" agent.py
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller (agent) failed' }
if ($CertThumbprint) { Get-ChildItem dist\AssetAgent -Recurse -Include *.exe | ForEach-Object { & signtool sign /sha1 $CertThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $_.FullName } }

# ---- 2. payload + setup (onefile, requests elevation)
$payload = "$PSScriptRoot\build\payload.zip"
if (Test-Path $payload) { Remove-Item $payload }
& $py -c "import shutil,sys; shutil.make_archive(sys.argv[1][:-4], 'zip', sys.argv[2])" $payload "$PSScriptRoot\dist\AssetAgent"
if ($LASTEXITCODE -ne 0) { throw 'Packing payload failed' }
& $py -m PyInstaller @common --onefile --uac-admin --name AssetAgentSetup --version-file "$PSScriptRoot\build\ver_setup.txt" `
  --add-data "$payload;." agent.py
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller (setup) failed' }
if ($CertThumbprint) { & signtool sign /sha1 $CertThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 dist\AssetAgentSetup.exe }

# ---- 3. publish to the portal
$dl = Join-Path $PSScriptRoot '..\server\downloads'
New-Item -ItemType Directory -Force $dl | Out-Null
Copy-Item dist\AssetAgentSetup.exe $dl -Force
Set-Content -Path (Join-Path $dl 'agent-version.txt') -Value $version -NoNewline
foreach ($old in 'AssetAgent.exe') { $p = Join-Path $dl $old; if (Test-Path $p) { Remove-Item $p } }
$size = [math]::Round((Get-Item dist\AssetAgentSetup.exe).Length / 1MB, 1)
Write-Host "OK -> $(Resolve-Path $dl)\AssetAgentSetup.exe  (v$version, $size MB)" -ForegroundColor Green
Write-Host 'Installed agents with an older version will upgrade themselves within a few minutes.'
