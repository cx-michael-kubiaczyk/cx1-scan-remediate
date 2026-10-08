#!/bin/sh
curdir=`pwd`
cd /tmp
curl -L https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_linux_x64.tar.gz -o ast-cli_linux_x64.tar.gz && tar -xvf ast-cli_linux_x64.tar.gz && rm ast-cli_linux_x64.tar.gz && chmod +x cx 
cd $curdir
/tmp/cx scan create --project-name "$PROJECT_NAME" -s . --branch "$BRANCH" --base-uri "$CX1_URL" --base-auth-uri "$IAM_URL" --tenant "$CX1_TENANT" --client-id "$CX1_CLIENT" --client-secret "$CX1_SECRET" --threshold "sast-critical=1;sast-high=1" --scan-types sast --report-format json 