#!/bin/sh
set -eu

# --- Configuration ---------------------------------------------------------
# Credentials and endpoints use the CX_* variables the AST CLI reads natively, so they never
# appear on its command line (where other processes and "set -x" logs could see them). The
# older names (CX1_URL, IAM_URL, CX1_TENANT, CX1_CLIENT, CX1_SECRET) are still accepted.
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
: "${GH_PR_PAT:?GH_PR_PAT is required (a token that can write to the target repository and raise pull requests)}"
if [ -z "$CX_APIKEY" ]; then
    : "${CX_BASE_AUTH_URI:?CX_BASE_AUTH_URI (or IAM_URL) is required unless CX_APIKEY is set}"
    : "${CX_TENANT:?CX_TENANT (or CX1_TENANT) is required unless CX_APIKEY is set}"
    : "${CX_CLIENT_ID:?CX_CLIENT_ID (or CX1_CLIENT) is required unless CX_APIKEY is set}"
    : "${CX_CLIENT_SECRET:?CX_CLIENT_SECRET (or CX1_SECRET) is required unless CX_APIKEY is set}"
fi

GH_REPO_URL="${GH_REPO_URL:-}"
proxy="${CX1SR_PROXY:-}"
cacert="${CX1SR_CACERT:-}"

# Optional TLS settings (e.g. behind a TLS-inspecting proxy):
#   CX1SR_CACERT:   path to a PEM file with the proxy's CA certificate(s); verification stays on
#   CX1SR_INSECURE: "true" to disable TLS verification entirely (not recommended)
case "${CX1SR_INSECURE:-}" in
    true|TRUE|True|1) insecure=1 ;;
    *) insecure="" ;;
esac
if [ -n "$insecure" ] && [ -n "$cacert" ]; then
    echo "CX1SR_INSECURE and CX1SR_CACERT are mutually exclusive" >&2
    exit 2
fi
if [ -n "$cacert" ] && [ ! -f "$cacert" ]; then
    echo "CX1SR_CACERT file not found: $cacert" >&2
    exit 2
fi

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

# --- Helpers ---------------------------------------------------------------
# curl for the downloads; honors CX1SR_PROXY and the TLS settings above
download() {
    if [ -n "$insecure" ]; then set -- -k "$@"; fi
    if [ -n "$cacert" ]; then set -- --cacert "$cacert" "$@"; fi
    if [ -n "$proxy" ]; then set -- --proxy "$proxy" "$@"; fi
    curl "$@"
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

# --- Scan ------------------------------------------------------------------
download -fsSL https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_linux_x64.tar.gz -o "$WORKDIR/ast-cli_linux_x64.tar.gz"
tar -xzf "$WORKDIR/ast-cli_linux_x64.tar.gz" -C "$WORKDIR"
chmod +x "$WORKDIR/cx"

# remove any stale report so its presence below means this scan produced it
rm -f cx_result.json

scan_rc=0
run_cx scan create --project-name "$PROJECT_NAME" -s . --branch "$BRANCH" --threshold "sast-critical=1;sast-high=1;sca-critical=1;sca-high=1;iac-security-critical=1;iac-security-high=1;api-security-critical=1;api-security-high=1;containers-critical=1;containers-high=1;sscs-secret-detection-critical=1;sscs-secret-detection-high=1;sscs-scorecard-critical=1;sscs-scorecard-high=1" --report-format json || scan_rc=$?

if [ "$scan_rc" -eq 0 ]; then
    exit 0
fi

if [ ! -f cx_result.json ]; then
    # no report was produced, so the scan itself failed (auth, network, download...) rather than breaking the threshold
    echo "Scan failed with exit code $scan_rc and produced no cx_result.json" >&2
    exit "$scan_rc"
fi

# --- Triage and remediate --------------------------------------------------
echo "Threshold exceeded"
if ! download -fsSL https://github.com/cx-michael-kubiaczyk/cx1-scan-remediate/releases/download/v0.0.10/cx1scanremediate -o "$WORKDIR/cx1scanremediate"; then
    echo "Could not download cx1scanremediate; the threshold failure stands" >&2
    exit "$scan_rc"
fi
chmod +x "$WORKDIR/cx1scanremediate"

# Optional arguments are built as positional parameters so values with spaces survive.
set --
if [ -n "$proxy" ]; then set -- "$@" -proxy "$proxy"; fi
if [ -n "${CX1SR_LOGLEVEL:-}" ]; then set -- "$@" -log "$CX1SR_LOGLEVEL"; fi
if [ -n "${CX1SR_TIMEOUT:-}" ]; then set -- "$@" -timeout "$CX1SR_TIMEOUT"; fi
if [ -n "$insecure" ]; then set -- "$@" -insecure; fi
if [ -n "$cacert" ]; then set -- "$@" -caCert "$cacert"; fi
case "${CX1SR_NO_KEEPALIVE:-}" in true|TRUE|True|1) set -- "$@" -noKeepAlive ;; esac

# TODO: the pinned v0.0.8 binary does not read the CX_* variables, so the Cx1 and GitHub
# credentials are still passed as flags here. After re-pinning to a release that does, drop
# -cx1/-iam/-tenant/-client/-secret/-apikey/-githubToken and let it read the environment.
if [ -n "$CX_APIKEY" ]; then
    set -- "$@" -apikey "$CX_APIKEY"
else
    set -- "$@" -iam "$CX_BASE_AUTH_URI" -tenant "$CX_TENANT" -client "$CX_CLIENT_ID" -secret "$CX_CLIENT_SECRET"
fi

tool_rc=0
"$WORKDIR/cx1scanremediate" -cx1 "$CX_BASE_URI" -triage 5 -remediate 1 -baseBranch "$BRANCH" -githubToken "$GH_PR_PAT" -repo "$GH_REPO_URL" -engine "sast,sca" -severity "CRITICAL,HIGH" "$@" || tool_rc=$?

# the gate was broken, so never pass: preserve the tool's failure, or fall back to the CLI's exit code
if [ "$tool_rc" -ne 0 ]; then
    exit "$tool_rc"
fi
exit "$scan_rc"
