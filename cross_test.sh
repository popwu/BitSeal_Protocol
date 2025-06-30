#!/usr/bin/env bash
# BitSeal Cross-Language Integration Test
# --------------------------------------
# 1. Go 生成签名 → TS 验证
# 2. TS 生成签名 → Go 验证
# 任何一步失败即退出非零

set -euo pipefail

GREEN="\033[0;32m"
RED="\033[0;31m"
NC="\033[0m"

# ───────────────────────────────────────
# Go → TS
# ───────────────────────────────────────

echo -e "${GREEN}Step 1: Go client signing …${NC}"
pushd gocode >/dev/null
go run ./cross/go_sign.go > ../go_sign.json
popd >/dev/null
echo -e "${GREEN}Step 2: TS server verifying …${NC}"
bun run tscode/cross/ts_verify.ts go_sign.json

# ───────────────────────────────────────
# TS → Go
# ───────────────────────────────────────

echo -e "${GREEN}Step 3: TS client signing …${NC}"
bun run tscode/cross/ts_sign.ts ts_sign.json
echo -e "${GREEN}Step 4: Go server verifying …${NC}"
pushd gocode >/dev/null
go run ./cross/go_verify.go ../ts_sign.json
popd >/dev/null

echo -e "${GREEN}All BitSeal cross tests passed successfully 🎉${NC}" 