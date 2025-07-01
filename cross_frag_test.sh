#!/usr/bin/env bash
# Cross-language fragment test (Go ↔ TS)
set -euo pipefail

GREEN="\033[0;32m"
NC="\033[0m"

printf "${GREEN}1. Go dump frames ...${NC}\n"
pushd gocode >/dev/null
go run ./rtc_cross_frag/go_dump.go ../frames_go.json
popd >/dev/null

printf "${GREEN}2. TS verify & re-encode ...${NC}\n"
bun run tscode/rtc_cross/ts_check.ts frames_go.json frames_ts.json

printf "${GREEN}3. Go verify TS frames ...${NC}\n"
pushd gocode >/dev/null
go run ./rtc_cross_frag/go_verify.go ../frames_ts.json
popd >/dev/null

printf "${GREEN}Cross-fragment test passed 🎉${NC}\n" 