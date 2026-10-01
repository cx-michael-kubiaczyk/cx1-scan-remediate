#!/bin/sh
curdir=`pwd`
cd /tmp
curl -L https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_linux_x64.tar.gz -o ast-cli_linux_x64.tar.gz && tar -xvf ast-cli_linux_x64.tar.gz && rm ast-cli_linux_x64.tar.gz && chmod +x cx 
cd $curdir
/tmp/cx scan create --project-name "$PROJECT_NAME" -s . --branch "$BRANCH" --base-uri "$CX1_URL" --base-auth-uri "$IAM_URL" --tenant "$CX1_TENANT" --client-id "$CX1_CLIENT" --client-secret "$CX1_SECRET" --threshold "sast-critical=1;sast-high=1" --scan-types sast --report-format json  || { 
    echo "Threshold exceeded"; 
    curl -L https://github.com/cx-michael-kubiaczyk/cx1-scan-remediate/releases/download/v0.0.5/cx1scanremediate -o /tmp/cx1scanremediate 
    chmod +x /tmp/cx1scanremediate
    extra_args=""
    if [ -n "$CX1SR_PROXY" ]; then
        extra_args="$extra_args -proxy $CX1SR_PROXY"
    fi
    if [ -n "$CX1SR_LOGLEVEL" ]; then
        extra_args="$extra_args -log $CX1SR_LOGLEVEL"
    fi

    /tmp/cx1scanremediate -cx1 "$CX1_URL" -iam "$IAM_URL" -tenant "$CX1_TENANT" -client "$CX1_CLIENT" -secret "$CX1_SECRET" -remediate 1 -baseBranch "$BRANCH" -githubToken "$GH_PR_PAT" -repo "$GH_REPO_URL" -engine "sast" $extra_args
}