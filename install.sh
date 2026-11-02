#!/usr/bin/env sh
# sp1cy reverse — installer (Linux / macOS)
# Usage:
#   ./install.sh            # Claude Code -> ~/.claude/skills/sp1cyreverse/SKILL.md
#   ./install.sh codex      # Codex CLI   -> ~/.codex/prompts/sp1cyreverse.md
set -eu

AGENT="${1:-claude}"
SRC="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/SKILL.md"

[ -f "$SRC" ] || { echo "SKILL.md not found next to install.sh" >&2; exit 1; }

case "$AGENT" in
  claude)
    DEST="$HOME/.claude/skills/sp1cyreverse"
    mkdir -p "$DEST"
    cp "$SRC" "$DEST/SKILL.md"
    echo "Installed: $DEST/SKILL.md"
    echo "Invoke with /sp1cyreverse (or let the description trigger it)."
    ;;
  codex)
    mkdir -p "$HOME/.codex/prompts"
    sed '1,/^---$/d; 1,/^---$/d' "$SRC" > "$HOME/.codex/prompts/sp1cyreverse.md"
    echo "Installed: $HOME/.codex/prompts/sp1cyreverse.md"
    echo "Invoke with /sp1cyreverse in Codex."
    ;;
  *)
    echo "Unknown agent: $AGENT (use: claude | codex)" >&2
    exit 1
    ;;
esac
