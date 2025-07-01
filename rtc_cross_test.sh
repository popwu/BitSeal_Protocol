#!/usr/bin/env bash
# BitSeal-RTC Cross-Language Integration Test
# -------------------------------------------
# 1. Go 端握手 → TS 端校验
# 2. TS 端握手 → Go 端校验
# 任一步失败即返回非零

set -euo pipefail

GREEN="\033[0;32m"
NC="\033[0m"

echo -e "${GREEN}Step 0: Go unit tests …${NC}"
pushd gocode >/dev/null
go test ./rtc -v
popd >/dev/null

echo -e "${GREEN}Step 0b: TS unit tests …${NC}"
bun test tscode/rtc

# ───────────────────────────────────────
# Go → TS
# ───────────────────────────────────────

echo -e "${GREEN}Step 1: Go RTC handshake …${NC}"
pushd gocode >/dev/null
go run ./rtc_cross/go_rtc_sign.go > ../go_rtc.json
popd >/dev/null

echo -e "${GREEN}Step 2: TS RTC verify …${NC}"
bun run tscode/rtc_cross/ts_rtc_verify.ts go_rtc.json

# ───────────────────────────────────────
# TS → Go
# ───────────────────────────────────────

echo -e "${GREEN}Step 3: TS RTC handshake …${NC}"
bun run tscode/rtc_cross/ts_rtc_sign.ts ts_rtc.json

echo -e "${GREEN}Step 4: Go RTC verify …${NC}"
pushd gocode >/dev/null
go run ./rtc_cross_verify/go_rtc_verify.go ../ts_rtc.json
popd >/dev/null

echo -e "${GREEN}All BitSeal-RTC cross tests passed successfully 🎉${NC}" 