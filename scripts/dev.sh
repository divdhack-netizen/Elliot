#!/usr/bin/env bash
# Elliot — dev helper per lo sviluppo locale. Vedi `scripts/dev.sh --help`.
set -euo pipefail

# Root del repo = dir genitore di questo script (robusto alla cwd).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Elliot — dev helper. Sottocomandi per lo sviluppo locale.

  scripts/dev.sh agent:setup   crea il venv del sidecar + installa le deps
  scripts/dev.sh dev           avvia l'app Tauri in modalità dev
EOF
  exit "${1:-0}"
}

agent_setup() {
  echo ">> agent:setup — venv + requirements"
  python3 -m venv "$ROOT/agent/.venv"
  "$ROOT/agent/.venv/bin/pip" install --upgrade pip
  "$ROOT/agent/.venv/bin/pip" install -r "$ROOT/agent/requirements.txt"
  echo ">> fatto. Sidecar: $ROOT/agent/.venv/bin/python -m elliot_agent"
}

dev() {
  echo ">> dev — tauri dev"
  cd "$ROOT/app"
  npm run tauri dev
}

cmd="${1:-}"
case "$cmd" in
  agent:setup) agent_setup ;;
  dev)         dev ;;
  -h|--help|help|"") usage 0 ;;
  *) echo "Sottocomando sconosciuto: $cmd" >&2; usage 1 ;;
esac
