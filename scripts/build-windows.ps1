<# Native Windows builder. Requires imported official BuildPhpExtension module.
   Run natively on Windows 11 x64 for PHP 8.2-8.5 NTS/TS (docs/WINDOWS-VALIDATION.md). #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('8.2','8.3','8.4','8.5')][string]$PhpVersion,
    [ValidateSet('nts','ts')][string]$ThreadSafety = 'nts',
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    # Optional: run the native integration tests (tests/test_native.py) against the built DLL with
    # this key pair: the PRIVATE owner file and the PRIVATE recipient file (e.g. test_owner.json and
    # test_recip.json from init-owner / init-recipient --no-encrypt), not the exported .pub file.
    [string]$Owner = '',
    [string]$Recipient = ''
)
$ErrorActionPreference = 'Stop'
# Defense in depth (ENV-2026-02): never let an inherited variable pull the bytecode emit/run surface
# into a server DLL. This builder compiles envelock_bcpoc.c without any --enable-envelock-bc* define,
# so its guarded bodies are empty; clearing these makes that intent explicit and inheritance-proof.
Remove-Item Env:ENVELOCK_BCPOC, Env:ENVELOCK_BCEMIT, Env:ENVELOCK_BCRUN -ErrorAction SilentlyContinue
$root = Split-Path $PSScriptRoot -Parent
$ownerFile = if ($Owner -ne '') { (Resolve-Path $Owner).Path } else { '' }
$recipientFile = if ($Recipient -ne '') { (Resolve-Path $Recipient).Path } else { '' }
# Fail before a long build, not after it: the native test fixture reads these as private configs, and
# an exported public key (.pub) fails there with "Incorrect config kind".
function Get-EnvelockKind([string]$Path) {
    try { return [string](Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json).kind }
    catch { throw "$Path is not an Envelock JSON key file." }
}
if ($ownerFile -ne '' -and (Get-EnvelockKind $ownerFile) -notin @('envelock-owner', 'envelock-encrypted')) {
    throw "-Owner must be the PRIVATE owner file (kind envelock-owner): $ownerFile"
}
if ($recipientFile -ne '') {
    $recipientKind = Get-EnvelockKind $recipientFile
    if ($recipientKind -eq 'envelock-recipient-public') {
        throw "-Recipient must be the PRIVATE recipient file (e.g. test_recip.json), not its exported public key: $recipientFile"
    }
    if ($recipientKind -notin @('envelock-recipient', 'envelock-encrypted')) {
        throw "-Recipient is not an Envelock recipient file (kind envelock-recipient): $recipientFile"
    }
}
if (($ownerFile -eq '') -ne ($recipientFile -eq '')) { throw 'Give both -Owner and -Recipient, or neither.' }
$keepOutput = $false
$testsFailed = $false
$createdOutput = $false
$output = [System.IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path $output) { throw 'OutputDirectory already exists; refusing to overwrite.' }
if (-not (Get-Command Invoke-PhpBuildExtension -ErrorAction SilentlyContinue)) {
    throw 'Import the official php/php-windows-builder BuildPhpExtension module first. See docs/PLATAFORMAS.md.'
}
$scratch = Join-Path ([System.IO.Path]::GetTempPath()) ('envelock-' + [Guid]::NewGuid())
$source = Join-Path $scratch 'envelock'
$build = Join-Path $scratch 'build'
New-Item -ItemType Directory -Path $source -Force | Out-Null
$oldLocation = Get-Location
$oldBuild = $env:BUILD_DIRECTORY
$oldRunTests = $env:RUN_TESTS
$oldPath = $env:PATH
$oldExt = $env:ENVELOCK_TEST_EXTENSION
$oldOwner = $env:ENVELOCK_TEST_OWNER
$oldRecipient = $env:ENVELOCK_TEST_RECIPIENT
$oldRequire = $env:ENVELOCK_REQUIRE_NATIVE
# The official BuildPhpExtension module's Add-Path writes the build's temporary php-sdk / php-bin
# folders into the PERSISTENT user PATH (HKCU\Environment) on every build. Save it (and the machine
# PATH, should an elevated build touch it) and restore it afterwards.
$persistentPath = @{}
foreach ($scope in 'User', 'Machine') {
    $persistentPath[$scope] = [Environment]::GetEnvironmentVariable('Path', $scope)
}
try {
    # Every top-level source and header plus the per-version bytecode layer, not a hand-kept list:
    # config.w32 (PHP_NEW_EXTENSION) is the authority on what compiles. The old 6-file list drifted
    # and dropped the 2.0 sources (envelock_secret/integrity/licence/clock/trusted_time/vm/bcpoc) and
    # the opcache/ layer, so the build failed on the first missing #include and, had it linked, would
    # have produced a source-only loader with no bytecode (config.w32 keys have_bc off opcache/).
    Copy-Item (Join-Path $root 'extension/*.c') $source
    Copy-Item (Join-Path $root 'extension/*.h') $source
    Copy-Item (Join-Path $root 'extension/config.w32') $source
    Copy-Item (Join-Path $root 'extension/opcache') $source -Recurse
    # The module is generic: it embeds no keys, so there is no build-time key step.
    $env:BUILD_DIRECTORY = $build
    $env:RUN_TESTS = 'false'
    Set-Location $source
    Invoke-PhpBuildExtension -PhpVersion $PhpVersion -Arch x64 -Ts $ThreadSafety -Libraries 'openssl' -Args '--enable-envelock=shared'
    $archives = @(Get-ChildItem (Join-Path $source 'artifacts') -File -Filter '*.zip')
    if ($archives.Count -ne 1) { throw 'Expected exactly one extension artifact ZIP.' }
    $expanded = Join-Path $scratch 'expanded'
    Expand-Archive -Path $archives[0].FullName -DestinationPath $expanded
    $module = @(Get-ChildItem $expanded -Recurse -Filter '*.dll' | Where-Object { $_.Name -match 'envelock' })
    if ($module.Count -ne 1) { throw 'Envelock DLL missing or ambiguous.' }
    New-Item -ItemType Directory -Path $output | Out-Null
    $createdOutput = $true
    Copy-Item $module[0].FullName (Join-Path $output 'php_envelock.dll')
    # Curated runtime output: NO PDBs, headers, JSON secrets or builder logs.
    Get-ChildItem $expanded -Recurse -File | Where-Object { $_.Name -match '^lib(crypto|ssl).*\.dll$' -or $_.Name -match '^LICENSE' } | ForEach-Object {
        Copy-Item $_.FullName $output
    }
    $runtimes = @(Get-ChildItem $build -Recurse -Filter 'php.exe' | Where-Object { $_.Directory.Name -eq 'php-bin' })
    if ($runtimes.Count -ne 1) { throw 'Native PHP test runtime missing or ambiguous in the SDK build tree.' }
    $runtime = $runtimes[0].FullName
    & $runtime -n -d opcache.enable=0 -d opcache.enable_cli=0 -d "extension=$output/php_envelock.dll" --ri envelock
    if ($LASTEXITCODE -ne 0) { throw 'DLL load smoke test failed.' }
    # Runtime exposure gate (ENV-2026-02), as build-unix.sh and build-static-php.sh do: a server DLL
    # must expose NEITHER the bytecode emitter NOR the runner. Asked of the loaded module itself. The
    # PHP code holds no double quotes, which Windows PowerShell 5.1 strips from native arguments.
    $exposed = & $runtime -n -d opcache.enable=0 -d opcache.enable_cli=0 -d "extension=$output/php_envelock.dll" -r "echo (function_exists('envelock_bc_run') || function_exists('envelock_bc_emit')) ? 'EXPOSED' : 'ok';"
    if ($LASTEXITCODE -ne 0 -or "$exposed".Trim() -ne 'ok') {
        throw 'SECURITY: this server DLL exposes the bytecode emit/run surface (ENV-2026-02); refusing to ship it.'
    }
    # Privacy gate: the shipped DLL must not carry the builder's paths (profile, user name, TEMP build
    # directory). __FILE__ (zend_bailout(), OpenSSL's memory macros) and the linker's default absolute
    # PDB path would put them there; the sources and config.w32 avoid both, and this asserts it.
    $dllText = [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes((Join-Path $output 'php_envelock.dll')))
    foreach ($needle in @($env:USERPROFILE, [System.IO.Path]::GetTempPath().TrimEnd('\'), $scratch, $root) | Where-Object { $_ }) {
        foreach ($form in @($needle, (($needle.ToCharArray() | ForEach-Object { "$_`0" }) -join ''))) {
            if ($dllText.IndexOf($form, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                throw "PRIVACY: the DLL embeds a build-machine path ($needle); refusing to ship it."
            }
        }
    }
    if ($ownerFile -ne '' -and $recipientFile -ne '') {
        $env:PATH = "$(Split-Path $runtime -Parent);$output;$oldPath"
        $env:ENVELOCK_TEST_EXTENSION = Join-Path $output 'php_envelock.dll'
        $env:ENVELOCK_TEST_OWNER = $ownerFile
        $env:ENVELOCK_TEST_RECIPIENT = $recipientFile
        $env:ENVELOCK_REQUIRE_NATIVE = '1'
        Set-Location $root
        # The native suite against this DLL (what the docs describe), not the whole test tree.
        python -m pytest -q tests/test_native.py
        if ($LASTEXITCODE -ne 0) { $testsFailed = $true }
    }
    if ($testsFailed) {
        # Keep the freshly built DLL for inspection (no SHA256SUMS.txt: it is not a release); only
        # the script fails.
        $keepOutput = $true
        throw "Native PHP integration tests (tests/test_native.py) failed; the DLL is kept, unpublished, in $output."
    }
    Get-ChildItem $output -File | ForEach-Object {
        "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower())  $($_.Name)"
    } | Set-Content (Join-Path $output 'SHA256SUMS.txt')
    Write-Host "Native Windows build complete: $output"
} catch {
    if ($createdOutput -and -not $keepOutput -and (Test-Path $output)) { Remove-Item $output -Recurse -Force }
    throw
} finally {
    Set-Location $oldLocation
    $env:BUILD_DIRECTORY = $oldBuild
    $env:RUN_TESTS = $oldRunTests
    $env:PATH = $oldPath
    $env:ENVELOCK_TEST_EXTENSION = $oldExt
    $env:ENVELOCK_TEST_OWNER = $oldOwner
    $env:ENVELOCK_TEST_RECIPIENT = $oldRecipient
    $env:ENVELOCK_REQUIRE_NATIVE = $oldRequire
    foreach ($scope in 'User', 'Machine') {
        if ([Environment]::GetEnvironmentVariable('Path', $scope) -ne $persistentPath[$scope]) {
            try { [Environment]::SetEnvironmentVariable('Path', $persistentPath[$scope], $scope) }
            catch { Write-Warning "Could not restore the $scope PATH changed by the builder: $_" }
        }
    }
    Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
