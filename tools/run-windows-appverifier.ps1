param(
  [string] $BuildDirectory = 'builddir',
  [string] $OutputDirectory = 'builddir\appverifier-artifacts'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Captured {
  param(
    [Parameter(Mandatory = $true)] [string] $FilePath,
    [Parameter(Mandatory = $true)] [AllowEmptyCollection()]
      [string[]] $Arguments,
    [Parameter(Mandatory = $true)] [string] $LogPath
  )

  $saved_preference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $lines = & $FilePath @Arguments 2>&1
    $exit_code = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $saved_preference
  }
  $text = ($lines | Out-String)
  Set-Content -LiteralPath $LogPath -Value $text -Encoding UTF8
  [pscustomobject]@{ ExitCode = $exit_code; Output = $text }
}

function Assert-Success {
  param([object] $Result, [string] $Operation)

  if ($Result.ExitCode -ne 0) {
    throw "$Operation failed with exit code $($Result.ExitCode):`n$($Result.Output)"
  }
}

function Query-Target {
  param([string] $ImageName, [string] $LogPath)

  Invoke-Captured -FilePath $script:app_verifier -Arguments @(
    '-query', '*', '-for', $ImageName
  ) -LogPath $LogPath
}

function Assert-Target-Enabled {
  param([string] $ImageName, [string] $LogPath)

  $query = Query-Target -ImageName $ImageName -LogPath $LogPath
  Assert-Success $query "query AppVerifier settings for $ImageName"
  foreach ($layer in @('Handles', 'Leak')) {
    if ($query.Output -notmatch "Test \[$layer\] enabled") {
      throw "AppVerifier did not report $layer enabled for $ImageName"
    }
  }
}

function Assert-Target-Disabled {
  param([string] $ImageName, [string] $LogPath)

  $query = Query-Target -ImageName $ImageName -LogPath $LogPath
  Assert-Success $query "query cleared AppVerifier settings for $ImageName"
  if ($query.Output -match 'Test \[[^]]+\] enabled') {
    throw "AppVerifier settings remain enabled for $ImageName"
  }
}

function Clear-Target {
  param([string] $ImageName, [string] $EvidenceDirectory)

  $settings = Invoke-Captured -FilePath $script:app_verifier -Arguments @(
    '-delete', 'settings', '-for', $ImageName
  ) -LogPath (Join-Path $EvidenceDirectory 'delete-settings.txt')
  $logs = Invoke-Captured -FilePath $script:app_verifier -Arguments @(
    '-delete', 'logs', '-for', $ImageName
  ) -LogPath (Join-Path $EvidenceDirectory 'delete-logs.txt')
  Assert-Target-Disabled -ImageName $ImageName -LogPath (
    Join-Path $EvidenceDirectory 'query-after-delete.txt')
  if ($settings.ExitCode -ne 0 -and
      $settings.Output -notmatch '(?i)(no settings|not found|not configured)') {
    throw "could not clear AppVerifier settings for $ImageName"
  }
  if ($logs.ExitCode -ne 0 -and
      $logs.Output -notmatch '(?i)(no logs|not found)') {
    throw "could not clear AppVerifier logs for $ImageName"
  }
}

function Enable-Target {
  param([string] $ImageName, [string] $EvidenceDirectory)

  $enable = Invoke-Captured -FilePath $script:app_verifier -Arguments @(
    '-enable', 'Handles', 'Leak', '-for', $ImageName
  ) -LogPath (Join-Path $EvidenceDirectory 'enable.txt')
  Assert-Success $enable "enable AppVerifier for $ImageName"
  $configure = Invoke-Captured -FilePath $script:app_verifier -Arguments @(
    '-configure', '0x300', '0x901', '-for', $ImageName,
    '-with', 'ErrorReport=0x1C1', 'Flavor=0x2'
  ) -LogPath (Join-Path $EvidenceDirectory 'configure-stops.txt')
  Assert-Success $configure "configure AppVerifier stops for $ImageName"
  Assert-Target-Enabled -ImageName $ImageName -LogPath (
    Join-Path $EvidenceDirectory 'query-enabled.txt')
}

function New-Phase {
  param([string] $Name)

  $phase = Join-Path $script:output_root $Name
  if (Test-Path -LiteralPath $phase) {
    throw "phase evidence directory already exists: $phase"
  }
  New-Item -ItemType Directory -Path $phase | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $phase 'raw') | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $phase 'xml') | Out-Null
  (Resolve-Path -LiteralPath $phase).Path
}

function Export-Phase-Logs {
  param([string] $Phase)

  $phase_path = (Resolve-Path -LiteralPath $Phase).Path
  $entries = @()
  $appverifier_logs = Join-Path $phase_path 'AppVerifierLogs'
  $raw_logs = @()
  if (Test-Path -LiteralPath $appverifier_logs -PathType Container) {
    $raw_logs = @(Get-ChildItem -LiteralPath $appverifier_logs -Filter '*.dat' -File)
  }
  foreach ($raw in $raw_logs) {
    if ($raw.Directory.FullName -ne $appverifier_logs) {
      throw "AppVerifier log escaped its phase directory: $($raw.FullName)"
    }
    $raw_copy = Join-Path (Join-Path $phase_path 'raw') $raw.Name
    Copy-Item -LiteralPath $raw.FullName -Destination $raw_copy
    $xml_path = Join-Path (Join-Path $phase_path 'xml') (
      [System.IO.Path]::GetFileNameWithoutExtension($raw.Name) + '.xml')
    $conversion = Invoke-Captured -FilePath $script:app_verifier -Arguments @(
      '-logtoxml', $raw.FullName, $xml_path
    ) -LogPath ($xml_path + '.conversion.txt')
    Assert-Success $conversion "convert AppVerifier log $($raw.Name)"
    if (!(Test-Path -LiteralPath $xml_path)) {
      throw "AppVerifier did not create XML for $($raw.Name)"
    }
    try {
      [xml] $document = Get-Content -LiteralPath $xml_path -Raw
      $nodes = @($document.SelectNodes("//*[local-name()='logEntry']"))
    } catch {
      throw "malformed AppVerifier XML $xml_path`: $($_.Exception.Message)"
    }
    foreach ($node in $nodes) {
      $stop_text = $node.GetAttribute('StopCode')
      $stop_value = $null
      if ($stop_text -match '^(?:0x)?([0-9A-Fa-f]+)$') {
        $stop_value = [Convert]::ToUInt32($Matches[1], 16)
      }
      $entries += [pscustomobject]@{
        Layer = $node.GetAttribute('LayerName')
        Severity = $node.GetAttribute('Severity')
        StopCode = $stop_value
        StopCodeText = $stop_text
        XmlPath = $xml_path
      }
    }
  }
  $entries
}

function Assert-Clean-Entries {
  param([object[]] $Entries, [string] $PhaseName)

  $failures = @($Entries | Where-Object {
    $_.Layer -in @('Handles', 'Leak') -or $_.Severity -eq 'Error'
  })
  if ($failures.Count -ne 0) {
    throw "$PhaseName produced $($failures.Count) verifier stop(s)"
  }
}

function Invoke-Probe-Phase {
  param([ValidateSet('clean', 'invalid')] [string] $Mode)

  $phase_name = @{
    clean = 'clean-probe'
    invalid = 'invalid-probe'
  }[$Mode]
  $phase = New-Phase $phase_name
  $env:VERIFIER_LOG_PATH = $phase
  Clear-Target -ImageName $script:probe_image -EvidenceDirectory $phase
  Enable-Target -ImageName $script:probe_image -EvidenceDirectory $phase
  $result = Invoke-Captured -FilePath $script:probe_path -Arguments @(
    $Mode, $script:probe_dll_path
  ) -LogPath (Join-Path $phase 'process.txt')
  $entries = @(Export-Phase-Logs -Phase $phase)
  if ($Mode -eq 'clean') {
    if ($result.ExitCode -ne 0) {
      throw "clean AppVerifier probe exited $($result.ExitCode)"
    }
    Assert-Clean-Entries -Entries $entries -PhaseName 'clean probe'
  } else {
    $expected_layer = 'Handles'
    $expected_stop = 0x300
    $expected = @($entries | Where-Object {
      $_.Layer -eq $expected_layer -and $_.StopCode -eq $expected_stop
    })
    $unexpected = @($entries | Where-Object {
      !($_.Layer -eq $expected_layer -and $_.StopCode -eq $expected_stop)
    })
    if ($result.ExitCode -eq 0 -or $expected.Count -eq 0 -or
        $unexpected.Count -ne 0) {
      throw ("intentional $Mode did not produce only the expected terminating " +
        "AppVerifier stop; exit=$($result.ExitCode), " +
        "expected=$($expected.Count), unexpected=$($unexpected.Count)")
    }
  }
  Clear-Target -ImageName $script:probe_image -EvidenceDirectory $phase
}

function Invoke-Artifact-Suite {
  $phase = New-Phase 'artifact-suite'
  $env:VERIFIER_LOG_PATH = $phase
  Clear-Target -ImageName $script:suite_image -EvidenceDirectory $phase
  Enable-Target -ImageName $script:suite_image -EvidenceDirectory $phase
  $previous_gate_marker = [Environment]::GetEnvironmentVariable(
      'WYRELOG_APPVERIFIER_HANDLE_GATE', 'Process')
  try {
    [Environment]::SetEnvironmentVariable(
        'WYRELOG_APPVERIFIER_HANDLE_GATE', '1', 'Process')
    $result = Invoke-Captured -FilePath $script:meson_path -Arguments @(
      'test', '-C', $script:build_root, '--no-rebuild',
      'fact-artifact-namespace-windows',
      'fact-artifact-namespace-windows-main-sidecar',
      'fact-artifact-namespace-windows-sidecar-replacement-isolated',
      'fact-artifact-namespace-windows-temp-binding-replacement-isolated',
      'fact-artifact-namespace-windows-lock-entry-replacement-isolated',
      'fact-artifact-namespace-windows-temp-token-real-crash-recovery',
      'fact-artifact-namespace-windows-cross-process',
      'fact-artifact-namespace-windows-temp-root-spill-child-capabilities',
      'fact-artifact-namespace-windows-temp-root-wrapper-ownership',
      'fact-artifact-namespace-windows-mutation-handle-lifetime',
      '--print-errorlogs'
    ) -LogPath (Join-Path $phase 'meson-test.txt')
  } finally {
    [Environment]::SetEnvironmentVariable(
        'WYRELOG_APPVERIFIER_HANDLE_GATE', $previous_gate_marker, 'Process')
  }
  $entries = @(Export-Phase-Logs -Phase $phase)
  if ($result.ExitCode -ne 0) {
    throw "instrumented Windows artifact suite exited $($result.ExitCode)"
  }
  Assert-Clean-Entries -Entries $entries -PhaseName 'artifact suite'
  Clear-Target -ImageName $script:suite_image -EvidenceDirectory $phase
}

function Invoke-Secure-Fixture-With-RuntimePath {
  param([Parameter(Mandatory = $true)] [string] $LogPath)

  $previous_path = [Environment]::GetEnvironmentVariable('PATH', 'Process')
  $secure_path = if ([string]::IsNullOrEmpty($previous_path)) {
    $script:vcpkg_runtime_directory
  } else {
    $script:vcpkg_runtime_directory + [System.IO.Path]::PathSeparator +
      $previous_path
  }
  try {
    [Environment]::SetEnvironmentVariable('PATH', $secure_path, 'Process')
    $result = Invoke-Captured -FilePath $script:secure_temp_child_path -Arguments @(
    ) -LogPath $LogPath
  } finally {
    [Environment]::SetEnvironmentVariable('PATH', $previous_path, 'Process')
  }
  $result
}

function Invoke-Secure-Temp-Child {
  $phase = New-Phase 'secure-temp-child'
  $env:VERIFIER_LOG_PATH = $phase
  Clear-Target -ImageName $script:secure_temp_child_image -EvidenceDirectory $phase
  $loader_probe = Invoke-Secure-Fixture-With-RuntimePath -LogPath (
    Join-Path $phase 'loader-preflight.txt')
  Assert-Success $loader_probe 'launch secure temp-child loader preflight'
  Enable-Target -ImageName $script:secure_temp_child_image -EvidenceDirectory $phase
  $result = Invoke-Secure-Fixture-With-RuntimePath -LogPath (
    Join-Path $phase 'process.txt')
  $entries = @(Export-Phase-Logs -Phase $phase)
  if ($result.ExitCode -ne 0) {
    throw "instrumented secure temp-child fixture exited $($result.ExitCode)"
  }
  Assert-Clean-Entries -Entries $entries -PhaseName 'secure temp-child'
  Clear-Target -ImageName $script:secure_temp_child_image -EvidenceDirectory $phase
}

if ($env:OS -ne 'Windows_NT') {
  throw 'the Windows handle-verifier gate can run only on Windows'
}
if (![Environment]::Is64BitOperatingSystem -or
    ![Environment]::Is64BitProcess) {
  throw 'the Windows handle-verifier gate requires 64-bit Windows and PowerShell'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$administrator = $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (Test-Path -LiteralPath $OutputDirectory) {
  throw "refusing to mix AppVerifier evidence with existing path: $OutputDirectory"
}
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$script:output_root = (Resolve-Path -LiteralPath $OutputDirectory).Path
[ordered]@{
  started_at_utc = [DateTime]::UtcNow.ToString('o')
  requested_build_directory = $BuildDirectory
  output_directory = $script:output_root
  process_64_bit = [Environment]::Is64BitProcess
  administrator = $administrator
  runner_environment = $env:RUNNER_ENVIRONMENT
  runner_name = $env:RUNNER_NAME
} | ConvertTo-Json -Depth 2 | Set-Content -LiteralPath (
  Join-Path $script:output_root 'runner-started.json') -Encoding UTF8
if ($env:GITHUB_ACTIONS -eq 'true' -and
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
  throw 'CI Application Verifier requires a GitHub-hosted runner'
}
if (!$administrator) {
  throw 'Application Verifier requires an Administrator process'
}

$script:app_verifier = Join-Path $env:SystemRoot 'System32\appverif.exe'
$provisioned = $false
if (!(Test-Path -LiteralPath $script:app_verifier -PathType Leaf)) {
  $winget = (Get-Command winget -ErrorAction Stop).Source
  $provision = Invoke-Captured -FilePath $winget -Arguments @(
    'install', '--id', 'Microsoft.WindowsSDK.10.0.28000', '--exact',
    '--source', 'winget', '--silent', '--force',
    '--accept-package-agreements', '--accept-source-agreements',
    '--disable-interactivity', '--override',
    '/features OptionId.AvrfExternal /quiet /norestart'
  ) -LogPath (Join-Path $script:output_root 'provision-appverifier.txt')
  Assert-Success $provision 'install Windows SDK Application Verifier feature'
  $provisioned = $true
  if (!(Test-Path -LiteralPath $script:app_verifier -PathType Leaf)) {
    throw ('Windows SDK provisioning completed without installing the ' +
      'Application Verifier feature (OptionId.AvrfExternal)')
  }
}
$signature = Get-AuthenticodeSignature -LiteralPath $script:app_verifier
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate -eq $null -or
    $signature.SignerCertificate.Subject -notmatch 'Microsoft') {
  throw 'appverif.exe does not have a valid Microsoft Authenticode signature'
}
$version_info = (Get-Item -LiteralPath $script:app_verifier).VersionInfo
if ($version_info.OriginalFilename -ine 'appverif.exe' -or
    ($version_info.ProductName + ' ' + $version_info.FileDescription) -notmatch 'Application Verifier') {
  throw 'the signed System32 binary is not Microsoft Application Verifier'
}
$version_match = [regex]::Match(
  $version_info.FileVersion, '^(\d+)\.(\d+)\.(\d+)\.(\d+)')
if (!$version_match.Success -or $version_match.Groups[1].Value -ne '10' -or
    $version_match.Groups[2].Value -ne '0' -or
    $version_match.Groups[3].Value -notin @('26100', '28000')) {
  throw "unsupported AppVerifier file version: $($version_info.FileVersion)"
}
$app_verifier_hash = (
  Get-FileHash -Algorithm SHA256 -LiteralPath $script:app_verifier).Hash
if ($app_verifier_hash -notmatch '^[0-9A-F]{64}$') {
  throw 'could not validate the AppVerifier SHA-256 identity'
}

$script:meson_path = (Get-Command meson -ErrorAction Stop).Source
$script:build_root = (Resolve-Path -LiteralPath $BuildDirectory).Path
$vcpkg_installed_value = [Environment]::GetEnvironmentVariable(
  'VCPKG_INSTALLED_DIR', 'Process')
if ([string]::IsNullOrWhiteSpace($vcpkg_installed_value) -or
    $vcpkg_installed_value -notmatch '^[A-Za-z]:[\\/]' -or
    $vcpkg_installed_value.Contains([System.IO.Path]::PathSeparator) -or
    $vcpkg_installed_value -match '(?:^|[\\/])\.\.(?:[\\/]|$)' -or
    !(Test-Path -LiteralPath $vcpkg_installed_value -PathType Container)) {
  throw 'Windows AppVerifier requires VCPKG_INSTALLED_DIR'
}
$script:vcpkg_installed_directory = (
  Resolve-Path -LiteralPath $vcpkg_installed_value).Path
$vcpkg_runtime_value = Join-Path $script:vcpkg_installed_directory 'bin'
if (!(Test-Path -LiteralPath $vcpkg_runtime_value -PathType Container)) {
  throw 'Windows AppVerifier requires the vcpkg runtime directory'
}
$script:vcpkg_runtime_directory = (
  Resolve-Path -LiteralPath $vcpkg_runtime_value).Path
$expected_vcpkg_runtime = [System.IO.Path]::GetFullPath(
  (Join-Path $script:vcpkg_installed_directory 'bin'))
if (![string]::Equals($script:vcpkg_runtime_directory,
    $expected_vcpkg_runtime, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'Windows AppVerifier vcpkg runtime is not the literal bin child'
}
if ($env:GITHUB_ACTIONS -eq 'true') {
  $runner_temp_value = [Environment]::GetEnvironmentVariable(
    'RUNNER_TEMP', 'Process')
  if ([string]::IsNullOrWhiteSpace($runner_temp_value) -or
      $runner_temp_value -notmatch '^[A-Za-z]:[\\/]' -or
      $runner_temp_value.Contains([System.IO.Path]::PathSeparator) -or
      $runner_temp_value -match '(?:^|[\\/])\.\.(?:[\\/]|$)' -or
      !(Test-Path -LiteralPath $runner_temp_value -PathType Container)) {
    throw 'Windows AppVerifier requires canonical RUNNER_TEMP'
  }
  $script:runner_temp_directory = (
    Resolve-Path -LiteralPath $runner_temp_value).Path
  $runner_temp_prefix = [string]::Concat(
    $script:runner_temp_directory.TrimEnd([char[]]@(
      [System.IO.Path]::DirectorySeparatorChar,
      [System.IO.Path]::AltDirectorySeparatorChar)),
    [System.IO.Path]::DirectorySeparatorChar)
  if (!$script:vcpkg_installed_directory.StartsWith(
      $runner_temp_prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Windows AppVerifier vcpkg root escaped RUNNER_TEMP'
  }
}
$tests_root = Join-Path $script:build_root 'tests'
$script:probe_path = Join-Path $tests_root 'test-windows-appverifier-probe.exe'
$script:probe_dll_path = Join-Path $tests_root 'test-windows-appverifier-probe-dll.dll'
$suite_path = Join-Path $tests_root 'test-fact-artifact-namespace-windows.exe'
$script:secure_temp_child_path = Join-Path $tests_root (
  'test-secure-duckdb-temp-child-windows.exe')
foreach ($required in @($script:probe_path, $script:probe_dll_path, $suite_path,
    $script:secure_temp_child_path)) {
  if (!(Test-Path -LiteralPath $required -PathType Leaf)) {
    throw "required Windows verifier target is missing: $required"
  }
}
$script:probe_image = [System.IO.Path]::GetFileName($script:probe_path)
$script:suite_image = [System.IO.Path]::GetFileName($suite_path)
$script:secure_temp_child_image = [System.IO.Path]::GetFileName(
  $script:secure_temp_child_path)
$metadata = [ordered]@{
  appverifier_path = $script:app_verifier
  appverifier_sha256 = $app_verifier_hash
  appverifier_file_version = $version_info.FileVersion
  appverifier_product_version = $version_info.ProductVersion
  provision_package = 'Microsoft.WindowsSDK.10.0.28000'
  provisioned_this_run = $provisioned
  authenticode_status = $signature.Status.ToString()
  authenticode_subject = $signature.SignerCertificate.Subject
  administrator = $true
  os_version = [Environment]::OSVersion.VersionString
  process_64_bit = [Environment]::Is64BitProcess
  vcpkg_installed_directory = $script:vcpkg_installed_directory
  vcpkg_runtime_directory = $script:vcpkg_runtime_directory
  duckdb_linkage = 'source-pinned-static'
  probe_image = $script:probe_image
  suite_image = $script:suite_image
  secure_temp_child_image = $script:secure_temp_child_image
  layers = @('Handles', 'Leak')
  stops = @('0x300', '0x901')
  error_report = '0x1C1'
  flavor = '0x2'
  suite_selectors = @(
    'fact-artifact-namespace-windows',
    'fact-artifact-namespace-windows-main-sidecar',
    'fact-artifact-namespace-windows-sidecar-replacement-isolated',
    'fact-artifact-namespace-windows-temp-binding-replacement-isolated',
    'fact-artifact-namespace-windows-lock-entry-replacement-isolated',
    'fact-artifact-namespace-windows-temp-token-real-crash-recovery',
    'fact-artifact-namespace-windows-cross-process',
    'fact-artifact-namespace-windows-temp-root-spill-child-capabilities',
    'fact-artifact-namespace-windows-temp-root-wrapper-ownership',
    'fact-artifact-namespace-windows-mutation-handle-lifetime'
  )
}
$metadata | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (
  Join-Path $script:output_root 'environment.json') -Encoding UTF8

$primary_error = $null
$cleanup_errors = @()
try {
  Invoke-Probe-Phase -Mode clean
  Invoke-Probe-Phase -Mode invalid
  Invoke-Artifact-Suite
  Invoke-Secure-Temp-Child
} catch {
  $primary_error = $_
} finally {
  $cleanup_root = Join-Path $script:output_root 'final-cleanup'
  New-Item -ItemType Directory -Path $cleanup_root -Force | Out-Null
  $env:VERIFIER_LOG_PATH = $cleanup_root
  foreach ($image in @($script:probe_image, $script:suite_image,
      $script:secure_temp_child_image)) {
    $image_root = Join-Path $cleanup_root $image
    New-Item -ItemType Directory -Path $image_root -Force | Out-Null
    try {
      Clear-Target -ImageName $image -EvidenceDirectory $image_root
    } catch {
      $cleanup_errors += "$image`: $($_.Exception.Message)"
    }
  }
  [ordered]@{
    primary_error = if ($primary_error) { $primary_error.Exception.Message } else { $null }
    cleanup_errors = $cleanup_errors
    completed = $primary_error -eq $null -and $cleanup_errors.Count -eq 0
  } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (
    Join-Path $script:output_root 'result.json') -Encoding UTF8
}

if ($primary_error) {
  if ($cleanup_errors.Count -ne 0) {
    [Console]::Error.WriteLine(
      "cleanup errors:`n" + ($cleanup_errors -join "`n"))
  }
  throw $primary_error
}
if ($cleanup_errors.Count -ne 0) {
  throw ("AppVerifier cleanup failed:`n" + ($cleanup_errors -join "`n"))
}
Write-Host "Windows Application Verifier handle gate passed: $script:output_root"
