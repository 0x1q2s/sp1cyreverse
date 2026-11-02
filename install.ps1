# sp1cy reverse — installer (Windows)
# Usage:
#   .\install.ps1              # Claude Code  -> ~/.claude/skills/sp1cyreverse/SKILL.md
#   .\install.ps1 -Agent codex # Codex CLI    -> ~/.codex/prompts/sp1cyreverse.md
param(
    [ValidateSet("claude", "codex")]
    [string]$Agent = "claude"
)

$ErrorActionPreference = "Stop"
$src = Join-Path $PSScriptRoot "SKILL.md"
if (-not (Test-Path $src)) { throw "SKILL.md not found next to install.ps1" }

if ($Agent -eq "claude") {
    $dir = Join-Path $HOME ".claude\skills\sp1cyreverse"
    New-Item -ItemType Directory -Force $dir | Out-Null
    Copy-Item $src (Join-Path $dir "SKILL.md") -Force
    Write-Host "Installed: $dir\SKILL.md"
    Write-Host "Invoke with /sp1cyreverse (or let the description trigger it)."
}
else {
    $dir = Join-Path $HOME ".codex\prompts"
    New-Item -ItemType Directory -Force $dir | Out-Null
    $lines = Get-Content $src
    $seen = 0
    $body = foreach ($line in $lines) {
        if ($line -eq "---") {
            $seen++
            if ($seen -le 2) { continue }
        }
        if ($seen -ge 2) { $line }
    }
    $out = Join-Path $dir "sp1cyreverse.md"
    Set-Content -Path $out -Value $body -Encoding UTF8
    Write-Host "Installed: $out"
    Write-Host "Invoke with /sp1cyreverse in Codex."
}
