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

if [ -n "$proxy" ]; then
    curl -fsSL --proxy "$proxy" https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_linux_x64.tar.gz -o "$WORKDIR/ast-cli_linux_x64.tar.gz"
else
    curl -fsSL https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_linux_x64.tar.gz -o "$WORKDIR/ast-cli_linux_x64.tar.gz"
fi
tar -xzf "$WORKDIR/ast-cli_linux_x64.tar.gz" -C "$WORKDIR"
chmod +x "$WORKDIR/cx"

if [ -n "$proxy" ]; then set -- --proxy "$proxy"; else set --; fi
"$WORKDIR/cx" scan create --project-name "$PROJECT_NAME" -s . --branch "$BRANCH" --threshold "sast-critical=1;sast-high=1;sca-critical=1;sca-high=1;iac-security-critical=1;iac-security-high=1;api-security-critical=1;api-security-high=1;containers-critical=1;containers-high=1;sscs-secret-detection-critical=1;sscs-secret-detection-high=1;sscs-scorecard-critical=1;sscs-scorecard-high=1" --report-format json "$@"
