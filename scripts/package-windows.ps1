[CmdletBinding()]
param(
    [string]$BuildDirectory = "build-mingw",
    [string]$QtRoot = "C:\Qt\6.11.2\mingw_64",
    [string]$Version = "0.1.0"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$buildPath = Join-Path $projectRoot $BuildDirectory
$distRoot = Join-Path $projectRoot "dist"
$packageName = "PrismKey-$Version-windows-x64"
$packagePath = Join-Path $distRoot $packageName
$zipPath = Join-Path $distRoot "$packageName.zip"
$guiSource = Join-Path $buildPath "prismkey_gui.exe"
$cliSource = Join-Path $buildPath "prismkey.exe"
$deployTool = Join-Path $QtRoot "bin\windeployqt.exe"

foreach ($requiredPath in @($guiSource, $cliSource, $deployTool)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) { throw "Arquivo obrigatorio nao encontrado: $requiredPath" }
}

if (Test-Path -LiteralPath $packagePath) { Remove-Item -LiteralPath $packagePath -Recurse -Force }
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
New-Item -ItemType Directory -Path $packagePath -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $projectRoot "LICENSE") -Destination $packagePath
Copy-Item -LiteralPath (Join-Path $projectRoot "HELLO_WORLD.txt") -Destination $packagePath

& $deployTool --release --compiler-runtime --no-translations --dir $packagePath $guiSource
if ($LASTEXITCODE -ne 0) { throw "windeployqt falhou com codigo $LASTEXITCODE" }
Copy-Item -LiteralPath $guiSource -Destination (Join-Path $packagePath "PrismKey.exe")
Copy-Item -LiteralPath $cliSource -Destination (Join-Path $packagePath "prismkey.exe")

$opensslDll = Join-Path $buildPath "libcrypto-3-x64.dll"
if (-not (Test-Path -LiteralPath $opensslDll)) { throw "Dependencia OpenSSL nao encontrada: $opensslDll" }
Copy-Item -LiteralPath $opensslDll -Destination $packagePath
Compress-Archive -Path (Join-Path $packagePath "*") -DestinationPath $zipPath -CompressionLevel Optimal
Write-Host "Pacote criado: $zipPath"
