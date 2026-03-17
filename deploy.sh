#!/usr/bin/env bash
# deploy.sh — one-command deploy for dns-audit.com
#
# Usage:
#   ./deploy.sh "commit message"
#   ./deploy.sh                    # uses default message
#
# What it does:
#   1. Bumps ?v= cache-bust in index.html to current git short hash
#   2. Commits and pushes to origin main
#   3. SSHs to server, pulls, restarts dns-auditor service

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
REMOTE_HOST="marmot-droplet"
REMOTE_DIR="/home/marmot7/dns-security-auditor"
SERVICE_NAME="dns-auditor"
INDEX_FILE="$REPO_DIR/static/index.html"

cd "$REPO_DIR"

# ── 1. Cache-bust static assets ──────────────────────────────
HASH=$(git rev-parse --short HEAD)
# Replace ?v=<anything>" with ?v=<hash>"
sed -i "s/\?v=[a-zA-Z0-9_-]*\"/\?v=${HASH}\"/g" "$INDEX_FILE"

echo "  Cache-bust: ?v=${HASH}"

# ── 2. Commit & push ─────────────────────────────────────────
MSG="${1:-deploy: update to ${HASH}}"

git add -A
if git diff --cached --quiet; then
    echo "  No changes to commit — pushing existing commits."
else
    git commit -m "$MSG"
    echo "  Committed: $MSG"
fi

git push origin main
echo "  Pushed to origin/main."

# ── 3. Deploy to server ──────────────────────────────────────
echo "  Deploying to $REMOTE_HOST..."
ssh "$REMOTE_HOST" bash -s <<REMOTE
    set -e
    cd "$REMOTE_DIR"
    git pull --ff-only origin main
    sudo systemctl restart "$SERVICE_NAME"
    sleep 2
    echo "  Service status:"
    sudo systemctl is-active "$SERVICE_NAME"
REMOTE

echo ""
echo "  Deploy complete. Site: https://dns-audit.com"
