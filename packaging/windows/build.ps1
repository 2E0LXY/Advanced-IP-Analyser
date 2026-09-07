param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repoRoot
$version = & $Python -c "import sys; sys.path.insert(0, 'src'); from ip_analyser import __version__; print(__version__)"
if ($LASTEXITCODE -ne 0 -or $version -notmatch '^\d+\.\d+\.\d+$') {
    throw "Could not determine a valid application version"
}

$versionParts = $version.Split('.')
$versionFile = Join-Path $repoRoot "build\windows\version-info.txt"
$sourcePath = Join-Path $repoRoot "src"
$iconPath = Join-Path $sourcePath "ip_analyser\assets\advanced-ip-analyser.png"
$entryPath = Join-Path $repoRoot "packaging\windows\gui_entry.py"
New-Item -ItemType Directory -Force -Path (Split-Path $versionFile) | Out-Null
@"
VSVersionInfo(
  ffi=FixedFileInfo(filevers=($($versionParts[0]), $($versionParts[1]), $($versionParts[2]), 0),
                    prodvers=($($versionParts[0]), $($versionParts[1]), $($versionParts[2]), 0),
                    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[StringFileInfo([StringTable('040904B0', [
    StringStruct('CompanyName', '2E0LXY'),
    StringStruct('FileDescription', 'Advanced IP Analyser'),
    StringStruct('FileVersion', '$version'),
    StringStruct('InternalName', 'Advanced-IP-Analyser'),
    StringStruct('LegalCopyright', 'Copyright 2026 Daren Loxley; GPL-3.0-or-later'),
    StringStruct('OriginalFilename', 'Advanced-IP-Analyser.exe'),
    StringStruct('ProductName', 'Advanced IP Analyser'),
    StringStruct('ProductVersion', '$version')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])])
"@ | Set-Content -Path $versionFile -Encoding UTF8

& $Python -m PyInstaller --noconfirm --clean --onedir --windowed `
    --name "Advanced-IP-Analyser" `
    --distpath "dist\windows" --workpath "build\windows\pyinstaller" `
    --specpath "build\windows" --paths $sourcePath `
    --collect-data "ip_analyser" --collect-all "keyring" `
    --icon $iconPath --version-file $versionFile $entryPath
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

$compiler = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
if (-not (Test-Path -LiteralPath $compiler)) { throw "Inno Setup 6 is not installed" }
$sourceDir = (Resolve-Path "dist\windows\Advanced-IP-Analyser").Path
$outputDir = Join-Path $repoRoot "dist\windows-installer"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
& $compiler "/DAppVersion=$version" "/DSourceDir=$sourceDir" "/DOutputDir=$outputDir" `
    "packaging\windows\installer.iss"
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }

$installer = Join-Path $outputDir "Advanced-IP-Analyser-Setup-$version.exe"
if (-not (Test-Path -LiteralPath $installer)) { throw "Expected installer was not created" }
Get-FileHash -Algorithm SHA256 -LiteralPath $installer | ForEach-Object {
    "$($_.Hash.ToLowerInvariant())  $(Split-Path -Leaf $_.Path)"
} | Set-Content -Path (Join-Path $outputDir "SHA256SUMS-WINDOWS.txt") -Encoding ascii
Write-Output $installer
