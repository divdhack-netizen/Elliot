#!/usr/bin/env bash
# Impacchetta il sidecar Python in un binario singolo e lo mette dove Tauri si
# aspetta un sidecar: app/src-tauri/binaries/elliot-agent-<target-triple>.
#
# Uso:
#   scripts/build-sidecar.sh                 # triple dell'host
#   scripts/build-sidecar.sh x86_64-unknown-linux-gnu
#
# Poi, per un bundle che includa il sidecar:
#   npm --prefix app run tauri:build:sidecar
#
# In sviluppo non serve: il ponte Rust usa `python -m elliot_agent`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-$(rustc -vV | sed -n 's/^host: //p')}"

# Python usato per impacchettare. Il default è il venv di sviluppo; se
# PyInstaller non supporta quella versione, puntare ELLIOT_PACK_PYTHON a un
# interprete supportato (es. un venv con 3.12/3.13) senza toccare il venv di
# sviluppo: `ELLIOT_PACK_PYTHON=/path/to/python scripts/build-sidecar.sh`.
PYTHON="${ELLIOT_PACK_PYTHON:-$ROOT/agent/.venv/bin/python}"
if [[ ! -x "$PYTHON" ]]; then
  echo "manca il venv del sidecar: esegui prima 'scripts/dev.sh agent:setup'" >&2
  exit 1
fi

if ! "$PYTHON" -c "import PyInstaller" >/dev/null 2>&1; then
  echo ">> installo PyInstaller nel venv del sidecar"
  "$PYTHON" -m pip install --quiet "pyinstaller>=6"
fi

OUT="$ROOT/app/src-tauri/binaries"
WORK="$ROOT/target/pyinstaller"
mkdir -p "$OUT" "$WORK"

# PyInstaller non risolve gli import relativi se gli si passa `__main__.py`:
# serve un entry point minimo che importi il pacchetto.
ENTRY="$WORK/elliot_agent_entry.py"
cat >"$ENTRY" <<'PY'
from elliot_agent.__main__ import main

main()
PY

# Il catalogo è dato di configurazione dentro il pacchetto: senza, il binario
# impacchettato non potrebbe proporre nulla (la validazione resta nel Rust).
if [[ "$OSTYPE" == msys* || "$OSTYPE" == cygwin* ]]; then
  DATA_SEP=";"
else
  DATA_SEP=":"
fi

"$PYTHON" -m PyInstaller \
  --onefile \
  --name elliot-agent \
  --paths "$ROOT/agent" \
  --add-data "$ROOT/catalog${DATA_SEP}catalog" \
  --distpath "$OUT" \
  --workpath "$WORK" \
  --specpath "$WORK" \
  --noconfirm \
  "$ENTRY"

mv "$OUT/elliot-agent" "$OUT/elliot-agent-$TARGET"
echo ">> sidecar pronto: $OUT/elliot-agent-$TARGET"
echo ">> bundle: npm --prefix app run tauri:build:sidecar"
