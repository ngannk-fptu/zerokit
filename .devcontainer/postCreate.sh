#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOCAL_BIN="${HOME}/.local/bin"

cd "${REPO_ROOT}"

mkdir -p "${LOCAL_BIN}" \
  "${REPO_ROOT}/.devcontainer/state/a/xdg-config" \
  "${REPO_ROOT}/.devcontainer/state/a/xdg-data" \
  "${REPO_ROOT}/.devcontainer/state/a/xdg-cache" \
  "${REPO_ROOT}/.devcontainer/state/b/xdg-config" \
  "${REPO_ROOT}/.devcontainer/state/b/xdg-data" \
  "${REPO_ROOT}/.devcontainer/state/b/xdg-cache"

ln -sf "${REPO_ROOT}/.devcontainer/bin/opencode-profile" "${LOCAL_BIN}/opencode-profile"
ln -sf "${REPO_ROOT}/.devcontainer/bin/opencode-a" "${LOCAL_BIN}/opencode-a"
ln -sf "${REPO_ROOT}/.devcontainer/bin/opencode-b" "${LOCAL_BIN}/opencode-b"
ln -sf "${REPO_ROOT}/.devcontainer/bin/opencode-sync" "${LOCAL_BIN}/opencode-sync"
ln -sf "${REPO_ROOT}/.devcontainer/bin/opencode-reset" "${LOCAL_BIN}/opencode-reset"

uv sync --extra dev --extra tools

if command -v opencode >/dev/null 2>&1; then
  opencode --version
else
  echo "warning: opencode is not on PATH after container build" >&2
fi

if command -v bun >/dev/null 2>&1; then
  bun --version
else
  echo "warning: bun is not on PATH after container build" >&2
fi
