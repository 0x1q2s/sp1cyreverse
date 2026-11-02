# sp1cy reverse — one-command GitHub publisher
#
# Creates (or reuses) the repository, pushes the current folder, then sets the
# description, homepage and topics in one go.
#
# Usage:
#   .\publish.ps1                       # publish under the logged-in gh account
#   .\publish.ps1 -Owner 0x1q2s         # publish under a specific account/org
#   .\publish.ps1 -Private              # private repo
#   .\publish.ps1 -DryRun               # print what would happen, change nothing
#
# Requirements: git, GitHub CLI (gh) authenticated with repo scope.

param(
    [string]$Name = "sp1cyreverse",
    [string]$Owner = "",
    [string]$Description = "Agent skill for reconstructing Java classes from JVM memory dumps - HotSpot metaspace, bytecode de-quickening, lazy body decryption, native lifting, and Minecraft client recovery. Built for Claude Code, Codex and OpenCode.",
    [string]$Homepage = "https://sp1cy.dev",
    [string]$CommitMessage = "feat: sp1cy reverse skill",
    [string[]]$Topics = @(
        "reverse-engineering",
        "jvm",
        "hotspot",
        "java",
        "bytecode",
        "minidump",
        "metaspace",
        "minecraft",
        "fabric",
        "agent-skills",
        "claude-code",
        "codex",
        "security-research"
    ),
    [switch]$Private,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$repoRoot = $PSScriptRoot

function Invoke-Tool {
    param([string]$Exe, [string[]]$Argv)
    if ($DryRun) {
        Write-Host ("[dry-run] {0} {1}" -f $Exe, ($Argv -join " "))
        return
    }
    & $Exe @Argv
    if ($LASTEXITCODE -ne 0) { throw "$Exe failed with exit code $LASTEXITCODE" }
}

# --- preflight ---------------------------------------------------------------

if (-not (Test-Path (Join-Path $repoRoot "SKILL.md"))) {
    throw "SKILL.md not found in $repoRoot"
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw "git is not installed" }
if (-not (Get-Command gh  -ErrorAction SilentlyContinue)) { throw "GitHub CLI (gh) is not installed" }
if ($Description.Length -gt 350) { throw "Description is longer than GitHub's 350 character limit" }
if ($Topics.Count -gt 20) { throw "GitHub allows at most 20 topics" }

& gh auth status 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { throw "gh is not authenticated. Run: gh auth login" }

$login = (& gh api user -q .login).Trim()
if (-not $Owner) { $Owner = $login }
$full = "$Owner/$Name"
$visibility = if ($Private) { "--private" } else { "--public" }

if ($Owner -ne $login) {
    Write-Warning "gh is authenticated as '$login', but the target owner is '$Owner'."
    Write-Warning "Repo creation will fail unless '$login' has permission on '$Owner'."
    Write-Warning "Switch accounts with: gh auth switch   (or: gh auth login)"
}

Write-Host "Target : https://github.com/$full"
Write-Host "Source : $repoRoot"
if ($DryRun) { Write-Host "Mode   : dry-run (no changes)" }

Push-Location $repoRoot
try {
    # --- git identity + repo ------------------------------------------------

    $gitEmail = (& git config user.email) 2>$null
    if (-not $gitEmail) {
        Invoke-Tool git @("config", "user.email", "$login@users.noreply.github.com")
        Invoke-Tool git @("config", "user.name", $login)
    }

    if (-not (Test-Path ".git")) {
        Invoke-Tool git @("init")
    }

    Invoke-Tool git @("add", "-A")
    if (-not $DryRun) {
        $dirty = & git status --porcelain
        if ($dirty) {
            Invoke-Tool git @("commit", "-m", $CommitMessage)
        } else {
            Write-Host "Nothing to commit."
        }
    }
    Invoke-Tool git @("branch", "-M", "main")

    # --- create repo if needed ----------------------------------------------

    $exists = $false
    if (-not $DryRun) {
        $previous = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
        & gh repo view $full --json name 1>$null 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $exists = $true }
        $ErrorActionPreference = $previous
    }

    if (-not $exists) {
        Invoke-Tool gh @(
            "repo", "create", $full, $visibility,
            "--description", $Description,
            "--homepage", $Homepage
        )
    } else {
        Write-Host "Repository already exists, reusing it."
    }

    # --- remote + push -------------------------------------------------------

    $hasRemote = $false
    if (-not $DryRun) {
        $previous = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
        & git remote get-url origin 1>$null 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $hasRemote = $true }
        $ErrorActionPreference = $previous
    }

    if (-not $hasRemote) {
        Invoke-Tool git @("remote", "add", "origin", "https://github.com/$full.git")
    } else {
        Invoke-Tool git @("remote", "set-url", "origin", "https://github.com/$full.git")
    }

    Invoke-Tool git @("push", "-u", "origin", "main")

    # --- description, homepage, topics --------------------------------------

    $ghArgs = @("repo", "edit", $full, "--description", $Description, "--homepage", $Homepage)
    foreach ($topic in $Topics) { $ghArgs += @("--add-topic", $topic) }
    Invoke-Tool gh $ghArgs

    Write-Host ""
    Write-Host "Done: https://github.com/$full"
    Write-Host "Topics: $($Topics -join ', ')"
}
finally {
    Pop-Location
}
