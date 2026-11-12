#!/bin/sh
curdir=`pwd`

# Optional TLS settings (e.g. behind a TLS-inspecting proxy):
#   CX1SR_CACERT:   path to a PEM file with the proxy's CA certificate(s); verification stays on
#   CX1SR_INSECURE: "true" to disable TLS verification entirely (not recommended)
case "$CX1SR_INSECURE" in
    true|TRUE|True|1) insecure=1 ;;
    *) insecure="" ;;
esac
if [ -n "$insecure" ] && [ -n "$CX1SR_CACERT" ]; then
    echo "CX1SR_INSECURE and CX1SR_CACERT are mutually exclusive" >&2
    exit 2
fi
if [ -n "$CX1SR_CACERT" ] && [ ! -f "$CX1SR_CACERT" ]; then
    echo "CX1SR_CACERT file not found: $CX1SR_CACERT" >&2
    exit 2
fi

# curl for the downloads
download() {
    if [ -n "$insecure" ]; then
        curl -k "$@"
    elif [ -n "$CX1SR_CACERT" ]; then
        curl --cacert "$CX1SR_CACERT" "$@"
    else
        curl "$@"
    fi
}

# the AST CLI has --insecure but no CA option; as a Go program it reads SSL_CERT_FILE (which replaces the system roots)
run_cx() {
    if [ -n "$insecure" ]; then
        /tmp/cx "$@" --insecure
    elif [ -n "$CX1SR_CACERT" ]; then
        SSL_CERT_FILE="$CX1SR_CACERT" /tmp/cx "$@"
    else
        /tmp/cx "$@"
    fi
}

cd /tmp
download -L https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_linux_x64.tar.gz -o ast-cli_linux_x64.tar.gz && tar -xvf ast-cli_linux_x64.tar.gz && rm ast-cli_linux_x64.tar.gz && chmod +x cx 
cd "$curdir"

# remove any stale report so its presence below means this scan produced it
rm -f cx_result.json

run_cx scan create --project-name "$PROJECT_NAME" -s . --branch "$BRANCH" --base-uri "$CX1_URL" --base-auth-uri "$IAM_URL" --tenant "$CX1_TENANT" --client-id "$CX1_CLIENT" --client-secret "$CX1_SECRET" --threshold "sast-critical=1;sast-high=1;sca-critical=1;sca-high=1;iac-security-critical=1;iac-security-high=1;api-security-critical=1;api-security-high=1;containers-critical=1;containers-high=1;sscs-secret-detection-critical=1;sscs-secret-detection-high=1;sscs-scorecard-critical=1;sscs-scorecard-high=1" --report-format json
scan_rc=$?

if [ "$scan_rc" -eq 0 ]; then
    exit 0
fi

if [ ! -f cx_result.json ]; then
    # no report was produced, so the scan itself failed (auth, network, download...) rather than breaking the threshold
    echo "Scan failed with exit code $scan_rc and produced no cx_result.json" >&2
    exit "$scan_rc"
fi

echo "Threshold exceeded"
download -L https://github.com/cx-michael-kubiaczyk/cx1-scan-remediate/releases/download/v0.0.8/cx1scanremediate -o /tmp/cx1scanremediate 
chmod +x /tmp/cx1scanremediate

# build the optional arguments as positional parameters so values with spaces survive
set --
if [ -n "$CX1SR_PROXY" ]; then set -- "$@" -proxy "$CX1SR_PROXY"; fi
if [ -n "$CX1SR_LOGLEVEL" ]; then set -- "$@" -log "$CX1SR_LOGLEVEL"; fi
if [ -n "$CX1SR_TIMEOUT" ]; then set -- "$@" -timeout "$CX1SR_TIMEOUT"; fi
if [ -n "$insecure" ]; then set -- "$@" -insecure; fi
if [ -n "$CX1SR_CACERT" ]; then set -- "$@" -caCert "$CX1SR_CACERT"; fi
case "$CX1SR_NO_KEEPALIVE" in true|TRUE|True|1) set -- "$@" -noKeepAlive ;; esac

/tmp/cx1scanremediate -cx1 "$CX1_URL" -iam "$IAM_URL" -tenant "$CX1_TENANT" -client "$CX1_CLIENT" -secret "$CX1_SECRET" -triage 5 -remediate 1 -baseBranch "$BRANCH" -githubToken "$GH_PR_PAT" -repo "$GH_REPO_URL" -engine "sast,sca" "$@" -severity "CRITICAL,HIGH"
tool_rc=$?

# the gate was broken, so never pass: preserve the tool's failure, or fall back to the CLI's exit code
if [ "$tool_rc" -ne 0 ]; then
    exit "$tool_rc"
fi
exit "$scan_rc"
