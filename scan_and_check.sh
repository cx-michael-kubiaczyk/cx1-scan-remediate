#!/bin/sh
set -eu

# --- Configuration ---------------------------------------------------------
# Required:
#   PROJECT_NAME, BRANCH   the Checkmarx One project and the branch being scanned
#   CX_BASE_URI            Checkmarx One URL, e.g. https://deu.ast.checkmarx.net
#   CX_APIKEY              or CX_BASE_AUTH_URI + CX_TENANT + CX_CLIENT_ID + CX_CLIENT_SECRET
#   GITHUB_PR_TOKEN        a token that can write to the target repository and raise pull requests
#                          (deliberately not GITHUB_TOKEN, so an ambient CI token is never used)
# Optional (defaults in brackets): CXSR_REPO (the project's repoUrl), CXSR_BASE_BRANCH [BRANCH],
#   CXSR_TRIAGE_COUNT [5], CXSR_REMEDIATE_COUNT [1], CXSR_ENGINES [sast,sca],
#   CXSR_SEVERITIES [CRITICAL,HIGH], CXSR_THRESHOLD [every engine, critical and high, at 1],
#   CXSR_LOG_LEVEL, CXSR_TIMEOUT, CXSR_PROXY, CXSR_CA_CERT, CXSR_INSECURE, CXSR_NO_KEEP_ALIVE,
#   CXSR_KEEP_TEMP, CXSR_VERSION [latest release], CXSR_RELEASE_REPO, CX_CLI_VERSION [latest],
#   CXSR_WORKDIR [a new temporary directory, removed on exit].
# Everything is passed to the AST CLI and to the cxscanremediate tool through the environment (see
# the README for each variable), so no credential ever appears on a command line, where other
# processes and "set -x" logs could see it.
: "${CX_BASE_URI:=}"
: "${CX_BASE_AUTH_URI:=}"
: "${CX_TENANT:=}"
: "${CX_CLIENT_ID:=}"
: "${CX_CLIENT_SECRET:=}"
: "${CX_APIKEY:=}"
export CX_BASE_URI CX_BASE_AUTH_URI CX_TENANT CX_CLIENT_ID CX_CLIENT_SECRET CX_APIKEY

: "${PROJECT_NAME:?PROJECT_NAME is required}"
: "${BRANCH:?BRANCH is required}"
: "${CX_BASE_URI:?CX_BASE_URI is required}"
: "${GITHUB_PR_TOKEN:?GITHUB_PR_TOKEN is required (a token that can write to the target repository and raise pull requests)}"
if [ -z "$CX_APIKEY" ]; then
    : "${CX_BASE_AUTH_URI:?CX_BASE_AUTH_URI is required unless CX_APIKEY is set}"
    : "${CX_TENANT:?CX_TENANT is required unless CX_APIKEY is set}"
    : "${CX_CLIENT_ID:?CX_CLIENT_ID is required unless CX_APIKEY is set}"
    : "${CX_CLIENT_SECRET:?CX_CLIENT_SECRET is required unless CX_APIKEY is set}"
fi

# Defaults for the tool; it reads these CXSR_* variables itself.
: "${CXSR_TRIAGE_COUNT:=5}"
: "${CXSR_REMEDIATE_COUNT:=1}"
: "${CXSR_ENGINES:=sast,sca}"
: "${CXSR_SEVERITIES:=CRITICAL,HIGH}"
: "${CXSR_BASE_BRANCH:=$BRANCH}"
export CXSR_TRIAGE_COUNT CXSR_REMEDIATE_COUNT CXSR_ENGINES CXSR_SEVERITIES CXSR_BASE_BRANCH

threshold="${CXSR_THRESHOLD:-sast-critical=1;sast-high=1;sca-critical=1;sca-high=1;iac-security-critical=1;iac-security-high=1;api-security-critical=1;api-security-high=1;containers-critical=1;containers-high=1;sscs-secret-detection-critical=1;sscs-secret-detection-high=1;sscs-scorecard-critical=1;sscs-scorecard-high=1}"
release_repo="${CXSR_RELEASE_REPO:-cx-michael-kubiaczyk/cx1-scan-remediate}"

proxy="${CXSR_PROXY:-}"
cacert="${CXSR_CA_CERT:-}"

# Optional TLS settings (e.g. behind a TLS-inspecting proxy):
#   CXSR_CA_CERT:  path to a PEM file with the proxy's CA certificate(s); verification stays on
#   CXSR_INSECURE: "true" to disable TLS verification entirely (not recommended)
case "${CXSR_INSECURE:-}" in
    true|TRUE|True|1) insecure=1 ;;
    *) insecure="" ;;
esac
if [ -n "$insecure" ] && [ -n "$cacert" ]; then
    echo "CXSR_INSECURE and CXSR_CA_CERT are mutually exclusive" >&2
    exit 2
fi
if [ -n "$cacert" ] && [ ! -f "$cacert" ]; then
    echo "CXSR_CA_CERT file not found: $cacert" >&2
    exit 2
fi

# A directory given in CXSR_WORKDIR is kept (it is the caller's); a temporary one is removed on exit.
if [ -n "${CXSR_WORKDIR:-}" ]; then
    WORKDIR="$CXSR_WORKDIR"
    mkdir -p "$WORKDIR"
    rm -f "$WORKDIR/cx_result.json"   # never mistake an earlier scan's report for this one's
else
    WORKDIR=$(mktemp -d)
    trap 'rm -rf "$WORKDIR"' EXIT
fi

# --- Helpers ---------------------------------------------------------------
# curl for the downloads; honors CXSR_PROXY and the TLS settings above. HTTPS only (also across
# redirects), TLS 1.2 or newer, transient failures retried, and bounded in time.
download() {
    if [ -n "$insecure" ]; then set -- -k "$@"; fi
    if [ -n "$cacert" ]; then set -- --cacert "$cacert" "$@"; fi
    if [ -n "$proxy" ]; then set -- --proxy "$proxy" "$@"; fi
    curl --proto "=https" --proto-redir "=https" --tlsv1.2 --retry 3 --retry-connrefused --connect-timeout 30 --max-time 600 "$@"
}

# Prints the tag of the latest release of GitHub repository $1 (owner/name), taken from the
# redirect that github.com/<repo>/releases/latest answers with.
latest_tag() {
    url=$(download -fsSIL -o /dev/null -w '%{url_effective}' "https://github.com/$1/releases/latest") || url=""
    case "$url" in
        */releases/tag/*) echo "${url##*/}" ;;
        *) echo "Could not determine the latest release of $1" >&2; return 1 ;;
    esac
}

# Checks that file $1 has the SHA-256 listed for asset name $3 in the checksums file $2
# (lines of "<sha256>  <name>", as published with each release). Exits 3 on any mismatch.
verify_checksum() {
    expected=$(tr -d '\r' < "$2" | awk -v n="$3" '$2 == n { print $1; exit }')
    if [ -z "$expected" ]; then
        echo "No checksum listed for $3; refusing to run it" >&2
        exit 3
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$1" | awk '{ print $1 }')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$1" | awk '{ print $1 }')
    else
        echo "Neither sha256sum nor shasum is available to verify $3" >&2
        exit 3
    fi
    if [ "$actual" != "$expected" ]; then
        echo "Checksum mismatch for $3 (expected $expected, got $actual); refusing to run it" >&2
        exit 3
    fi
}

# The AST CLI has --proxy and --insecure but no CA option; as a Go program it reads
# SSL_CERT_FILE (which replaces its system roots).
run_cx() {
    if [ -n "$insecure" ]; then set -- "$@" --insecure; fi
    if [ -n "$proxy" ]; then set -- "$@" --proxy "$proxy"; fi
    if [ -n "$cacert" ]; then
        SSL_CERT_FILE="$cacert" "$WORKDIR/cx" "$@"
    else
        "$WORKDIR/cx" "$@"
    fi
}

# --- Platform --------------------------------------------------------------
# Pick the AST CLI and tool assets for this machine, and fail early on anything else.
case "$(uname -s)/$(uname -m)" in
    Linux/x86_64|Linux/amd64) cli_platform=linux_x64;   tool_platform=linux_amd64 ;;
    Linux/aarch64|Linux/arm64) cli_platform=linux_arm64; tool_platform=linux_arm64 ;;
    *)
        echo "Unsupported platform $(uname -s)/$(uname -m): this script supports Linux on x86_64 and arm64 only" >&2
        exit 2
        ;;
esac

# --- Scan ------------------------------------------------------------------
# Resolve the latest AST CLI release once and fetch both the archive and its checksums from
# that exact tag, so they cannot come from two different releases. CX_CLI_VERSION pins one.
CX_CLI_VERSION="${CX_CLI_VERSION:-}"
if [ -z "$CX_CLI_VERSION" ]; then
    CX_CLI_VERSION=$(latest_tag Checkmarx/ast-cli) || exit 3
fi
cli_archive="ast-cli_${CX_CLI_VERSION}_${cli_platform}.tar.gz"
cli_base="https://github.com/Checkmarx/ast-cli/releases/download/${CX_CLI_VERSION}"
download -fsSL "$cli_base/$cli_archive" -o "$WORKDIR/$cli_archive"
download -fsSL "$cli_base/ast-cli_${CX_CLI_VERSION}_checksums.txt" -o "$WORKDIR/cli_checksums.txt"
verify_checksum "$WORKDIR/$cli_archive" "$WORKDIR/cli_checksums.txt" "$cli_archive"
tar -xzf "$WORKDIR/$cli_archive" -C "$WORKDIR"
chmod +x "$WORKDIR/cx"

# The report is written to the (fresh, temporary) work directory rather than the scanned source
# directory, so a stale report left in a cached or persisted workspace can never be mistaken
# for this scan's, and nothing is added to the customer's checkout.
report="$WORKDIR/cx_result.json"

scan_rc=0
run_cx scan create --project-name "$PROJECT_NAME" -s . --branch "$BRANCH" --threshold "$threshold" --report-format json --output-path "$WORKDIR" || scan_rc=$?

if [ "$scan_rc" -eq 0 ]; then
    exit 0
fi

if [ ! -f "$report" ]; then
    # no report was produced, so the scan itself failed (auth, network, download...) rather than breaking the threshold
    echo "Scan failed with exit code $scan_rc and produced no report" >&2
    exit "$scan_rc"
fi

# --- Triage and remediate --------------------------------------------------
echo "Threshold exceeded"
# The latest release of this tool unless CXSR_VERSION pins one (e.g. v0.0.11)
CXSR_VERSION="${CXSR_VERSION:-}"
if [ -z "$CXSR_VERSION" ]; then
    CXSR_VERSION=$(latest_tag "$release_repo") || { echo "The threshold failure stands" >&2; exit "$scan_rc"; }
fi
tool_base="https://github.com/$release_repo/releases/download/$CXSR_VERSION"
tool_asset="cxscanremediate_${tool_platform}"
if ! download -fsSL "$tool_base/$tool_asset" -o "$WORKDIR/cxscanremediate" ||
   ! download -fsSL "$tool_base/checksums.txt" -o "$WORKDIR/tool_checksums.txt"; then
    echo "Could not download cxscanremediate; the threshold failure stands" >&2
    exit "$scan_rc"
fi
verify_checksum "$WORKDIR/cxscanremediate" "$WORKDIR/tool_checksums.txt" "$tool_asset"
chmod +x "$WORKDIR/cxscanremediate"

# The tool reads its whole configuration from the environment (the CXSR_* variables above and
# CX_*, exported earlier), apart from the report location and the GitHub token below. Extra
# arguments given to this script are passed on to it. The token is set for the tool's process
# only. When an API key is used, the client credentials are removed from the tool's environment
# so it never has two methods to choose from.
tool_rc=0
if [ -n "$CX_APIKEY" ]; then
    CXSR_REPORT_FILE="$report" GITHUB_TOKEN="$GITHUB_PR_TOKEN" env -u CX_CLIENT_ID -u CX_CLIENT_SECRET "$WORKDIR/cxscanremediate" "$@" || tool_rc=$?
else
    CXSR_REPORT_FILE="$report" GITHUB_TOKEN="$GITHUB_PR_TOKEN" "$WORKDIR/cxscanremediate" "$@" || tool_rc=$?
fi

# the gate was broken, so never pass: preserve the tool's failure, or fall back to the CLI's exit code
if [ "$tool_rc" -ne 0 ]; then
    exit "$tool_rc"
fi
exit "$scan_rc"
