param(
    [string]$Sdk = (Join-Path $PSScriptRoot '../sdk-installed/ps5-payload-sdk'),
    [string]$LlvmBin = 'C:\Program Files\LLVM\bin',
    [switch]$Trace
)
$ErrorActionPreference = 'Stop'
$Sdk = (Resolve-Path -LiteralPath $Sdk).Path
$clang = Join-Path $LlvmBin 'clang.exe'
$linker = Join-Path $LlvmBin 'ld.lld.exe'
$build = Join-Path $PSScriptRoot 'build'
New-Item -ItemType Directory -Force -Path $build | Out-Null
$compileFlags = @(
    '-target', 'x86_64-sie-ps5', '-fvisibility-nodllstorageclass=default',
    '-isystem', (Join-Path $Sdk 'target/include'),
    '-fno-stack-protector', '-fno-plt', '-femulated-tls', '-O2', '-Wall', '-DDUMP_GAME'
)
if ($Trace) { $compileFlags += '-DSELF_PAGER_TRACE' }
foreach ($source in @('main', 'selfpager')) {
    & $clang @compileFlags -c (Join-Path $PSScriptRoot "$source.c") -o (Join-Path $build "$source.o")
    if ($LASTEXITCODE -ne 0) { throw "Compilation failed: $source.c" }
}
# Use the SDK's prospero-lld link settings directly, preserving paths with spaces.
$outputName = if ($Trace) { 'ps5-self-pager-game-progress.elf' } else { 'ps5-self-pager-game.elf' }
$output = Join-Path $PSScriptRoot $outputName
& $linker -m elf_x86_64 -pie --eh-frame-hdr -z max-page-size=0x4000 `
    -T (Join-Path $Sdk 'ldscripts/elf_x86_64.x') `
    -L (Join-Path $Sdk 'target/lib') -o $output `
    (Join-Path $Sdk 'target/lib/crt1.o') `
    (Join-Path $build 'main.o') (Join-Path $build 'selfpager.o') `
    -lc -lkernel_sys -lSceLibcInternal -lSceNet
if ($LASTEXITCODE -ne 0) { throw 'ELF linking failed' }
Get-Item -LiteralPath $output
Get-FileHash -LiteralPath $output -Algorithm SHA256
