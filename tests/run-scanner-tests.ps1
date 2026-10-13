param([string]$Clang = 'C:\Program Files\LLVM\bin\clang.exe')
$ErrorActionPreference = 'Stop'
$source = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '../main.c')
$start = $source.IndexOf('static const char *allowed_exts[]')
$end = $source.IndexOf('int main() {', $start)
if ($start -lt 0 -or $end -lt 0) { throw 'Cannot locate production scanner' }
$testDir = Join-Path ([System.IO.Path]::GetTempPath()) ('pager-scanner-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $testDir | Out-Null
Set-Content -LiteralPath (Join-Path $testDir 'scanner.inc') -Value $source.Substring($start, $end - $start) -Encoding utf8
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'scanner_test.c') -Destination $testDir
$exe = Join-Path $testDir 'scanner-test.exe'
& $Clang -Wall -Wextra -Wno-missing-field-initializers -Werror (Join-Path $testDir 'scanner_test.c') -o $exe
if ($LASTEXITCODE -ne 0) { throw 'Scanner test compilation failed' }
& $exe
if ($LASTEXITCODE -ne 0) { throw 'Scanner tests failed' }
$pager = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '../selfpager.c')
$start = $pager.IndexOf('void *map_self_segment(')
$end = $pager.IndexOf('int decrypt_self(', $start)
if ($start -lt 0 -or $end -lt 0) { throw 'Cannot locate production segment mapper' }
Set-Content -LiteralPath (Join-Path $testDir 'mapping.inc') -Value $pager.Substring($start, $end - $start) -Encoding utf8
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'mapping_test.c') -Destination $testDir
$mapperExe = Join-Path $testDir 'mapping-test.exe'
& $Clang -Wall -Wextra -Werror (Join-Path $testDir 'mapping_test.c') -o $mapperExe
if ($LASTEXITCODE -ne 0) { throw 'Mapping test compilation failed' }
& $mapperExe
if ($LASTEXITCODE -ne 0) { throw 'Mapping tests failed' }
function Extract-TestSource([string]$text, [string]$from, [string]$until, [string]$name) {
    $begin = $text.IndexOf($from)
    $finish = if ($until) { $text.IndexOf($until, $begin) } else { $text.Length }
    if ($begin -lt 0 -or $finish -lt 0) { throw "Cannot extract $name" }
    Set-Content -LiteralPath (Join-Path $testDir $name) -Value $text.Substring($begin, $finish - $begin) -Encoding utf8
}
Extract-TestSource $pager '#define SELF_ORBIS_MAGIC' '#ifdef SELF_PAGER_DO_LOGGING' 'self-constants.inc'
Extract-TestSource $pager 'struct sce_self_header {' 'static uint16_t fwver' 'self-structs.inc'
Extract-TestSource $pager '// Entry layout:' 'void *map_self_segment(' 'plain-reader.inc'
Extract-TestSource $pager 'int decrypt_self(' '' 'self-decrypt.inc'
$header = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '../selfpager.h')
Extract-TestSource $header '#define DECRYPT_SUCCESS_PLAINTEXT_SELF' '// Success is' 'self-errors.inc'
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'plain_self_test.c') -Destination $testDir
$plainExe = Join-Path $testDir 'plain-self-test.exe'
& $Clang -Wall -Wextra -Werror -Wno-sign-compare (Join-Path $testDir 'plain_self_test.c') -o $plainExe
if ($LASTEXITCODE -ne 0) { throw 'Plaintext reconstruction test compilation failed' }
& $plainExe
if ($LASTEXITCODE -ne 0) { throw 'Plaintext reconstruction tests failed' }
