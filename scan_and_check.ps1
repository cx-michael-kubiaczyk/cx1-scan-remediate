# PowerShell version of scan_and_check.sh for Windows agents (Windows PowerShell 5.1 or PowerShell 7).
#
# Runs a Checkmarx One scan with the AST CLI and, if the scan breaks the threshold, runs
# cxscanremediate to triage and remediate findings and open pull requests. The exit code is
# never 0 after a threshold break: the CLI's failure (or the tool's) is always preserved.
#
# Exit codes: the AST CLI's own code, or 1/3 from the tool; 2 for a usage/configuration/platform
# problem; 3 for a download or checksum failure.
#
# Configuration is the same as scan_and_check.sh (environment variables):
#   required: PROJECT_NAME, BRANCH, CX_BASE_URI, GITHUB_PR_TOKEN, and either CX_APIKEY or
#             CX_BASE_AUTH_URI + CX_TENANT + CX_CLIENT_ID + CX_CLIENT_SECRET
#   optional: CXSR_REPO, CXSR_BASE_BRANCH, CXSR_TRIAGE_COUNT, CXSR_REMEDIATE_COUNT, CXSR_ENGINES,
#             CXSR_SEVERITIES, CXSR_THRESHOLD, CXSR_LOG_LEVEL, CXSR_TIMEOUT, CXSR_PROXY,
#             CXSR_CA_CERT, CXSR_INSECURE, CXSR_NO_KEEP_ALIVE, CXSR_KEEP_TEMP, CXSR_VERSION,
#             CXSR_RELEASE_REPO, CX_CLI_VERSION, CXSR_WORKDIR
#   The tool reads its CXSR_* settings from the environment itself (see the README); GITHUB_PR_TOKEN is
#   deliberately not GITHUB_TOKEN, so that an ambient CI token is never used.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-Err([string]$Message) {
    [Console]::Error.WriteLine($Message)
}

function Stop-Script([int]$Code, [string]$Message) {
    Write-Err $Message
    exit $Code
}

# First non-empty of the named environment variables, or '' if none is set.
function Get-Env([string[]]$Names) {
    foreach ($n in $Names) {
        $v = [Environment]::GetEnvironmentVariable($n)
        if ($v) { return $v }
    }
    return ''
}

function Test-Flag([string]$Name) {
    return @('true', '1') -contains ([Environment]::GetEnvironmentVariable($Name) + '').ToLower()
}

# curl.exe (shipped with Windows 10 1803+ and Server 2019+) for the downloads, so that the proxy
# and TLS options behave exactly as in scan_and_check.sh. $script:Proxy, $script:CaCert and
# $script:Insecure come from the configuration.
function Invoke-Download([string[]]$CurlArgs) {
    $a = @()
    $a += @('--proto', '=https', '--proto-redir', '=https', '--tlsv1.2', '--retry', '3', '--retry-connrefused', '--connect-timeout', '30', '--max-time', '600')
    if ($script:Proxy) { $a += @('--proxy', $script:Proxy) }
    if ($script:CaCert) { $a += @('--cacert', $script:CaCert) }
    if ($script:Insecure) { $a += '-k' }
    $a += $CurlArgs
    & curl.exe @a
    if ($LASTEXITCODE -ne 0) { throw "curl.exe failed with exit code $LASTEXITCODE" }
}

# The tag of the latest release of GitHub repository $Repo (owner/name), taken from the redirect
# that github.com/<repo>/releases/latest answers with. Returns '' if it cannot be determined.
function Get-LatestTag([string]$Repo) {
    try {
        $out = Invoke-Download @('-fsSIL', '-o', 'NUL', '-w', '%{url_effective}', "https://github.com/$Repo/releases/latest")
        $url = ($out | Out-String).Trim()
    } catch {
        return ''
    }
    if ($url -match '/releases/tag/([^/]+)$') { return $Matches[1] }
    return ''
}

# Checks that file $Path has the SHA-256 listed for asset $Name in the checksums file
# $ChecksumFile (lines of "<sha256>  <name>", as published with each release). Exits 3 on a
# missing entry or a mismatch.
function Confirm-Checksum([string]$Path, [string]$ChecksumFile, [string]$Name) {
    $expected = ''
    foreach ($line in Get-Content -LiteralPath $ChecksumFile) {
        $parts = $line.Trim() -split '\s+'
        if ($parts.Count -ge 2 -and $parts[1] -eq $Name) { $expected = $parts[0]; break }
    }
    if (-not $expected) { Stop-Script 3 "No checksum listed for $Name; refusing to run it" }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actual -ne $expected.ToUpper()) {
        Stop-Script 3 "Checksum mismatch for $Name (expected $expected, got $($actual.ToLower())); refusing to run it"
    }
}

function Get-Architecture {
    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    return $arch
}

function Invoke-Main {
    # --- Configuration -----------------------------------------------------
    # Credentials and endpoints use the CX_* variables the AST CLI reads natively, so they never
    # appear on its command line.
    foreach ($req in @(
            @('PROJECT_NAME', 'PROJECT_NAME is required'),
            @('BRANCH', 'BRANCH is required'),
            @('CX_BASE_URI', 'CX_BASE_URI is required'),
            @('GITHUB_PR_TOKEN', 'GITHUB_PR_TOKEN is required (a token that can write to the target repository and raise pull requests)'))) {
        if (-not (Get-Env @($req[0]))) { Stop-Script 2 $req[1] }
    }
    if (-not $env:CX_APIKEY) {
        foreach ($req in @(
                @('CX_BASE_AUTH_URI', 'CX_BASE_AUTH_URI is required unless CX_APIKEY is set'),
                @('CX_TENANT', 'CX_TENANT is required unless CX_APIKEY is set'),
                @('CX_CLIENT_ID', 'CX_CLIENT_ID is required unless CX_APIKEY is set'),
                @('CX_CLIENT_SECRET', 'CX_CLIENT_SECRET is required unless CX_APIKEY is set'))) {
            if (-not (Get-Env @($req[0]))) { Stop-Script 2 $req[1] }
        }
    }

    # Defaults for the tool, which reads these CXSR_* variables itself.
    foreach ($d in @(
            @('CXSR_TRIAGE_COUNT', '5'), @('CXSR_REMEDIATE_COUNT', '1'),
            @('CXSR_ENGINES', 'sast,sca'), @('CXSR_SEVERITIES', 'CRITICAL,HIGH'),
            @('CXSR_BASE_BRANCH', $env:BRANCH))) {
        if (-not (Get-Env @($d[0]))) { [Environment]::SetEnvironmentVariable($d[0], $d[1], 'Process') }
    }
    $threshold = Get-Env @('CXSR_THRESHOLD')
    if (-not $threshold) { $threshold = 'sast-critical=1;sast-high=1;sca-critical=1;sca-high=1;iac-security-critical=1;iac-security-high=1;api-security-critical=1;api-security-high=1;containers-critical=1;containers-high=1;sscs-secret-detection-critical=1;sscs-secret-detection-high=1;sscs-scorecard-critical=1;sscs-scorecard-high=1' }
    $releaseRepo = Get-Env @('CXSR_RELEASE_REPO')
    if (-not $releaseRepo) { $releaseRepo = 'cx-michael-kubiaczyk/cx1-scan-remediate' }

    $script:Proxy = Get-Env @('CXSR_PROXY')
    $script:CaCert = Get-Env @('CXSR_CA_CERT')
    $script:Insecure = Test-Flag 'CXSR_INSECURE'
    if ($script:Insecure -and $script:CaCert) { Stop-Script 2 'CXSR_INSECURE and CXSR_CA_CERT are mutually exclusive' }
    if ($script:CaCert -and -not (Test-Path -LiteralPath $script:CaCert -PathType Leaf)) {
        Stop-Script 2 "CXSR_CA_CERT file not found: $($script:CaCert)"
    }
    if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
        Stop-Script 2 'curl.exe was not found; it ships with Windows 10 (1803+) and Windows Server 2019+'
    }

    # --- Platform ----------------------------------------------------------
    # Pick the AST CLI and tool assets for this machine, and fail early on anything else.
    $onWindows = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
    $arch = Get-Architecture
    if (-not $onWindows -or $arch -ne 'AMD64') {
        Stop-Script 2 "Unsupported platform ($arch): this script supports Windows on x64 only; use scan_and_check.sh on Linux"
    }
    $cliPlatform = 'windows_x64'
    $toolAsset = 'cxscanremediate_windows_amd64.exe'

    # A directory given in CXSR_WORKDIR is kept (it is the caller's); a temporary one is removed at the end.
    $ownWorkDir = -not (Get-Env @('CXSR_WORKDIR'))
    if ($ownWorkDir) {
        $workDir = Join-Path ([IO.Path]::GetTempPath()) ('cxsr-' + [Guid]::NewGuid().ToString('N'))
    } else {
        $workDir = Get-Env @('CXSR_WORKDIR')
    }
    New-Item -ItemType Directory -Force -Path $workDir | Out-Null
    # never mistake an earlier scan's report for this one's
    Remove-Item -LiteralPath (Join-Path $workDir 'cx_result.json') -Force -ErrorAction SilentlyContinue
    try {
        # --- Scan ----------------------------------------------------------
        # Resolve the latest AST CLI release once and fetch both the archive and its checksums from
        # that exact tag, so they cannot come from two different releases. CX_CLI_VERSION pins one.
        $cliVersion = Get-Env @('CX_CLI_VERSION')
        if (-not $cliVersion) {
            $cliVersion = Get-LatestTag 'Checkmarx/ast-cli'
            if (-not $cliVersion) { Stop-Script 3 'Could not determine the latest release of Checkmarx/ast-cli' }
        }
        $cliArchive = "ast-cli_${cliVersion}_${cliPlatform}.zip"
        $cliBase = "https://github.com/Checkmarx/ast-cli/releases/download/$cliVersion"
        try {
            Invoke-Download @('-fsSL', "$cliBase/$cliArchive", '-o', (Join-Path $workDir $cliArchive))
            Invoke-Download @('-fsSL', "$cliBase/ast-cli_${cliVersion}_checksums.txt", '-o', (Join-Path $workDir 'cli_checksums.txt'))
        } catch {
            Stop-Script 3 "Could not download the AST CLI ($cliVersion): $($_.Exception.Message)"
        }
        Confirm-Checksum (Join-Path $workDir $cliArchive) (Join-Path $workDir 'cli_checksums.txt') $cliArchive
        Expand-Archive -LiteralPath (Join-Path $workDir $cliArchive) -DestinationPath $workDir -Force
        $cx = Join-Path $workDir 'cx.exe'

        # The report is written to the temporary work directory rather than the scanned source
        # directory, so a stale report in a cached workspace can never be mistaken for this scan's.
        $report = Join-Path $workDir 'cx_result.json'

        $cxArgs = @('scan', 'create', '--project-name', $env:PROJECT_NAME, '-s', '.', '--branch', $env:BRANCH,
            '--threshold', $threshold,
            '--report-format', 'json', '--output-path', $workDir)
        if ($script:Insecure) { $cxArgs += '--insecure' }
        if ($script:Proxy) { $cxArgs += @('--proxy', $script:Proxy) }

        # The AST CLI has --proxy and --insecure but no CA option; as a Go program it reads
        # SSL_CERT_FILE (which replaces its system roots).
        $oldCert = $env:SSL_CERT_FILE
        if ($script:CaCert) { $env:SSL_CERT_FILE = $script:CaCert }
        try {
            & $cx @cxArgs
            $scanRc = $LASTEXITCODE
        } finally {
            $env:SSL_CERT_FILE = $oldCert
        }

        if ($scanRc -eq 0) { exit 0 }

        if (-not (Test-Path -LiteralPath $report)) {
            # no report was produced, so the scan itself failed (auth, network, download...) rather than breaking the threshold
            Stop-Script $scanRc "Scan failed with exit code $scanRc and produced no report"
        }

        # --- Triage and remediate ------------------------------------------
        Write-Host 'Threshold exceeded'
        # The latest release of this tool unless CXSR_VERSION pins one (e.g. v0.0.11)
        $toolVersion = Get-Env @('CXSR_VERSION')
        if (-not $toolVersion) {
            $toolVersion = Get-LatestTag $releaseRepo
            if (-not $toolVersion) { Stop-Script $scanRc 'Could not determine the latest cxscanremediate release; the threshold failure stands' }
        }
        $toolBase = "https://github.com/$releaseRepo/releases/download/$toolVersion"
        $tool = Join-Path $workDir 'cxscanremediate.exe'
        try {
            Invoke-Download @('-fsSL', "$toolBase/$toolAsset", '-o', $tool)
            Invoke-Download @('-fsSL', "$toolBase/checksums.txt", '-o', (Join-Path $workDir 'tool_checksums.txt'))
        } catch {
            Stop-Script $scanRc 'Could not download cxscanremediate; the threshold failure stands'
        }
        Confirm-Checksum $tool (Join-Path $workDir 'tool_checksums.txt') $toolAsset

        # The tool reads its whole configuration from the environment (the CXSR_* variables
        # above, CX_* and GITHUB_TOKEN), so nothing, least of all a credential, is on its
        # command line, where the process list could show it. Only the report location is set here.
        $toolArgs = @()

        # GITHUB_TOKEN and the report location are set for the tool's process only. When an API
        # key is used, the client credentials are removed from its environment so it never has
        # two methods to choose from.
        $oldReport = $env:CXSR_REPORT_FILE
        $env:CXSR_REPORT_FILE = $report
        $oldToken = $env:GITHUB_TOKEN
        $oldId = $env:CX_CLIENT_ID
        $oldSecret = $env:CX_CLIENT_SECRET
        $env:GITHUB_TOKEN = $env:GITHUB_PR_TOKEN
        if ($env:CX_APIKEY) {
            $env:CX_CLIENT_ID = $null
            $env:CX_CLIENT_SECRET = $null
        }
        try {
            & $tool @toolArgs
            $toolRc = $LASTEXITCODE
        } finally {
            $env:CXSR_REPORT_FILE = $oldReport
            $env:GITHUB_TOKEN = $oldToken
            $env:CX_CLIENT_ID = $oldId
            $env:CX_CLIENT_SECRET = $oldSecret
        }

        # the gate was broken, so never pass: preserve the tool's failure, or fall back to the CLI's exit code
        if ($toolRc -ne 0) { exit $toolRc }
        exit $scanRc
    } finally {
        if ($ownWorkDir) { Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# Run unless the file is dot-sourced (which lets the helper functions be tested on their own)
if ($MyInvocation.InvocationName -ne '.') { Invoke-Main }
