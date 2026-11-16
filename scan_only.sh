#!/bin/sh
set -eu

# Credentials and endpoints use the CX_* variables the AST CLI reads natively, so they never
# appear on its command line. The older names (CX1_URL, IAM_URL, ...) are still accepted.
CX_BASE_URI="${CX_BASE_URI:-${CX1_URL:-}}"
CX_BASE_AUTH_URI="${CX_BASE_AUTH_URI:-${IAM_URL:-}}"
CX_TENANT="${CX_TENANT:-${CX1_TENANT:-}}"
CX_CLIENT_ID="${CX_CLIENT_ID:-${CX1_CLIENT:-}}"
CX_CLIENT_SECRET="${CX_CLIENT_SECRET:-${CX1_SECRET:-}}"
CX_APIKEY="${CX_APIKEY:-${CX1_APIKEY:-}}"
export CX_BASE_URI CX_BASE_AUTH_URI CX_TENANT CX_CLIENT_ID CX_CLIENT_SECRET CX_APIKEY

: "${PROJECT_NAME:?PROJECT_NAME is required}"
: "${BRANCH:?BRANCH is required}"
: "${CX_BASE_URI:?CX_BASE_URI (or CX1_URL) is required}"
if [ -z "$CX_APIKEY" ]; then
    : "${CX_BASE_AUTH_URI:?CX_BASE_AUTH_URI (or IAM_URL) is required unless CX_APIKEY is set}"
    : "${CX_TENANT:?CX_TENANT (or CX1_TENANT) is required unless CX_APIKEY is set}"
    : "${CX_CLIENT_ID:?CX_CLIENT_ID (or CX1_CLIENT) is required unless CX_APIKEY is set}"
    : "${CX_CLIENT_SECRET:?CX_CLIENT_SECRET (or CX1_SECRET) is required unless CX_APIKEY is set}"
fi

proxy="${CX1SR_PROXY:-}"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

# curl for the downloads; honors CX1SR_PROXY
download() {
    if [ -n "$proxy" ]; then set -- --proxy "$proxy" "$@"; fi
    curl "$@"
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

# --- Platform --------------------------------------------------------------
# Pick the AST CLI and tool assets for this machine, and fail early on anything else.
case "$(uname -s)/$(uname -m)" in
    Linux/x86_64|Linux/amd64) cli_platform=linux_x64 ;;
    Linux/aarch64|Linux/arm64) cli_platform=linux_arm64 ;;
    *)
        echo "Unsupported platform $(uname -s)/$(uname -m): this script supports Linux on x86_64 and arm64 only" >&2
        exit 2
        ;;
esac

# Resolve the latest AST CLI release once and fetch both the archive and its checksums from
# that exact tag. CX_CLI_VERSION pins one.
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

if [ -n "$proxy" ]; then set -- --proxy "$proxy"; else set --; fi
"$WORKDIR/cx" scan create --project-name "$PROJECT_NAME" -s . --branch "$BRANCH" --threshold "sast-critical=1;sast-high=1;sca-critical=1;sca-high=1;iac-security-critical=1;iac-security-high=1;api-security-critical=1;api-security-high=1;containers-critical=1;containers-high=1;sscs-secret-detection-critical=1;sscs-secret-detection-high=1;sscs-scorecard-critical=1;sscs-scorecard-high=1" --report-format json "$@"
