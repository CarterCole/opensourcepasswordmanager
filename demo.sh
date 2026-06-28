#!/usr/bin/env bash
# demo.sh — start secretd locally for testing
# Requires: docker, cargo, npm (for rebuilding UI)
set -e

SECRETD_PORT=${SECRETD_PORT:-8200}
UI_URL="http://localhost:${SECRETD_PORT}/ui/"
DEV_TOKEN="dev-root-token"

# ── colours ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RESET='\033[0m'
info()  { echo -e "${CYAN}▶ $*${RESET}"; }
ok()    { echo -e "${GREEN}✓ $*${RESET}"; }
warn()  { echo -e "${YELLOW}! $*${RESET}"; }

cleanup() {
    info "Stopping…"
    kill "$SERVER_PID" 2>/dev/null || true
    docker compose stop postgres 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── 1. Start Postgres ─────────────────────────────────────────────────────────
info "Starting Postgres via docker compose…"
docker compose up -d postgres
info "Waiting for Postgres to be healthy…"
until docker compose exec -T postgres pg_isready -U secretd -q 2>/dev/null; do
    sleep 1
done
ok "Postgres ready"

# ── 2. Build UI (if source is newer than dist) ───────────────────────────────
if [ ! -f web/dist/index.html ] || \
   find web/src -newer web/dist/index.html -name "*.tsx" -o -name "*.ts" -o -name "*.css" 2>/dev/null | grep -q .; then
    info "Building UI…"
    (cd web && npm install --silent && npm run build --silent)
    ok "UI built"
else
    ok "UI already up to date"
fi

# ── 3. Compile secretd with embedded UI ──────────────────────────────────────
info "Compiling secretd (with embedded UI)…"
cargo build --features embed-ui --quiet
ok "Compiled"

# ── 4. Export env and run server ──────────────────────────────────────────────
export DATABASE_URL="postgres://secretd:secretd@localhost:5432/secretd"
export SECRETD_LISTEN="127.0.0.1:${SECRETD_PORT}"
export SECRETD_DEV_ROOT_TOKEN="${DEV_TOKEN}"
export SECRETD_JWT_SECRET="demo-jwt-secret"
export SECRETD_KEK_ID="00000000-0000-0000-0000-000000000001"
export SECRETD_KEK="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="   # 32 zero bytes (demo only)

info "Starting secretd on port ${SECRETD_PORT}…"
./target/debug/secretd &
SERVER_PID=$!

# Wait for server to be ready
for i in $(seq 1 20); do
    if curl -sf "http://localhost:${SECRETD_PORT}/v1/sys/health" >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

if ! curl -sf "http://localhost:${SECRETD_PORT}/v1/sys/health" >/dev/null 2>&1; then
    echo "Server failed to start. Check output above."
    exit 1
fi
ok "Server ready"

# ── 5. Print quick-start info ─────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${GREEN}  secretd is running!${RESET}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "  ${CYAN}Dashboard${RESET}    ${UI_URL}"
echo -e "  ${CYAN}Token${RESET}        ${DEV_TOKEN}"
echo -e "  ${CYAN}Vault API${RESET}    http://localhost:${SECRETD_PORT}/v1/"
echo -e "  ${CYAN}AWS shim${RESET}     http://localhost:${SECRETD_PORT}/"
echo ""
echo -e "  ${YELLOW}Quick test:${RESET}"
echo -e "    vault kv put secret/myapp db_pass=hunter2"
echo -e "    vault kv get secret/myapp"
echo ""
echo -e "  ${YELLOW}AWS CLI test:${RESET}"
echo -e "    AWS_ENDPOINT_URL=http://localhost:${SECRETD_PORT} \\"
echo -e "    AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \\"
echo -e "    aws secretsmanager create-secret --name myapp/db --secret-string hunter2"
echo ""
echo -e "  ${YELLOW}boto3 / API keys:${RESET}"
echo -e "    curl -s -X POST http://localhost:${SECRETD_PORT}/api/v1/keys \\"
echo -e "      -H 'Authorization: Bearer ${DEV_TOKEN}' \\"
echo -e "      -H 'Content-Type: application/json' \\"
echo -e "      -d '{\"name\":\"ci\",\"role\":\"developer\"}' | jq ."
echo ""
echo "Press Ctrl-C to stop."
echo ""

# ── 6. Open browser ──────────────────────────────────────────────────────────
if command -v xdg-open &>/dev/null; then
    xdg-open "${UI_URL}" 2>/dev/null &
elif command -v open &>/dev/null; then
    open "${UI_URL}" &
fi

# Keep running until Ctrl-C
wait "$SERVER_PID"
