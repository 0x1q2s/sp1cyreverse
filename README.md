# sp1cy reverse

> Reconstruct Java `.class` files from a JVM memory dump when the JAR on disk is encrypted, obfuscated, or gutted.

![skill](https://img.shields.io/badge/skill-SKILL.md-111111)
![agents](https://img.shields.io/badge/agents-Claude%20Code%20%7C%20Codex%20%7C%20OpenCode-111111)
![license](https://img.shields.io/badge/license-MIT-111111)

**sp1cy reverse** is an agent skill — a single `SKILL.md` playbook — for JVM
reverse engineering. It takes a minidump or full process dump plus a protected
artifact and walks the agent from raw memory to clean, decompilable class files.

It is built for the real cases: custom `jvm.dll` builds with wiped exports,
per-method lazy body encryption, native JVMTI loaders, VM-virtualized bytecode,
and Minecraft clients that fight back with anti-dump and anti-emulation tricks.

## What it covers

- **HotSpot metaspace** — `InstanceKlass`, `ConstantPool`, `Method`,
  `ConstMethod`, `ConstantPoolCache`, symbol layouts, array headers.
- **Offset discovery** — export-based vtables when `jvm.dll` is intact,
  self-calibration anchored on `java/lang/Object` / `java/lang/String` when
  exports are stripped. Calibration is cached; layouts are never assumed.
- **Bytecode de-quickening** — `fast_*` opcodes, cpCache entries, legacy vs
  resolved-array layouts, invokedynamic operand rules, custom opcode remaps.
- **Correct class emission** — natural code end instead of trusting `code_size`,
  canary neutralization, exception-table filtering, access-flag cleanup.
- **Decrypt location triage** — Java class loader / Fabric transformer /
  native JVM / FFI native, with a different route for each.
- **Cold-method recovery** — hotter dumps, hot-carve from a live process,
  late-attach JVMTI, VEH + hardware breakpoints, forced loading.
- **Native lifting** — Unicorn emulation of the real decoder, `JNI_OnLoad`
  mapping, native→Java rewrite.
- **Minecraft specifics** — Fabric mod packaging, native shim, offline bring-up,
  render/UI/worldgen repair, online-layer removal.
- **Appendices** — Rust reconstructor skeleton, JVMTI agent, string recovery,
  asset carving, VM devirtualization, report templates.

## Requirements

The skill is method-first: tools are referenced by role, not by absolute path.
A typical setup:

- Python 3 with `unicorn`, `capstone`, `pefile`, `lief`
- radare2 (`rabin2`, `r2`), Ghidra (headless) for native work
- CFR and Vineflower as decompiler oracles, `javap` for structural checks
- A JDK matching the target major version
- Optional: a Rust workspace for the reconstructor/emulator base
  (see Appendix N in `SKILL.md`)

## Install

### Claude Code

```bash
git clone https://github.com/0x1q2s/sp1cyreverse.git
mkdir -p ~/.claude/skills/sp1cyreverse
cp sp1cyreverse/SKILL.md ~/.claude/skills/sp1cyreverse/SKILL.md
```

Or run the installer:

```powershell
# Windows
.\install.ps1
```

```bash
# Linux / macOS
./install.sh
```

The skill becomes `/sp1cyreverse` and also triggers automatically from its
description. No restart is required.

### Codex CLI

Codex reads slash commands from `~/.codex/prompts/`. Strip the YAML front
matter and write the body:

```bash
mkdir -p ~/.codex/prompts
sed '1,/^---$/d; 1,/^---$/d' SKILL.md > ~/.codex/prompts/sp1cyreverse.md
```

Invoke with `/sp1cyreverse`.

### Other agents

Any agent that supports folder-based skills can load this repository: keep
`SKILL.md` at the root of a folder named `sp1cyreverse` in the agent's skills
directory. For project-local use, copy it to `<repo>/.claude/skills/sp1cyreverse/`.

## Usage

Point the agent at the dump and the protected artifact:
```text
Here's client.dmp and the encrypted client.jar. The jvm.dll is custom,
probably JDK 21. Reconstruct the classes and decompile them.
```

```text
Bodies are encrypted and only hot methods come out. Find where decryption
happens and recover the cold methods.
```

```text
The reconstructed Fabric client loads but the menu and HUD never render.
Figure out what the dump lost and fix the render path.
```

The skill forces the agent to profile the artifact first, prove the JDK build,
choose exports vs. calibration, validate against anchor classes, and report
what was recovered and what was not — instead of guessing offsets.

## How it works

```text
dump / live process
        │
        ├─ parse Memory64List / modules ──► VA→file reader
        │
        ├─ locate InstanceKlass objects ──► exports or calibration
        │
        ├─ rebuild constant pool + methods
        │
        ├─ de-quicken bytecode (cpCache)
        │
        ├─ detect cold/encrypted bodies
        │     ├─ Java-side decrypt ──► heap CAFEBABE carve
        │     ├─ native lazy decrypt ──► emulate decoder / hotter dump
        │     └─ FFI native ──► native→Java lift
        │
        └─ emit valid ClassFile ──► CFR / Vineflower / javap
```

## Repository layout

```text
sp1cyreverse/
├─ SKILL.md        # the full playbook (English)
├─ README.md       # this file
├─ LICENSE         # MIT
├─ .gitignore      # keeps dumps, jars and keys out of git
├─ install.ps1     # Windows installer
├─ install.sh      # Linux / macOS installer
└─ publish.ps1     # one-command GitHub publish (repo + description + topics)
```

Maintainer publish:

```powershell
.\publish.ps1 -Owner 0x1q2s
```

It creates (or reuses) the repo, pushes `main`, then sets the description,
homepage and topics. Add `-Private` or `-DryRun` as needed.

## Scope and legal

Use this only on artifacts you own or have explicit permission to analyze.
It is a reverse-engineering and interoperability playbook, not a license to
attack third-party systems. Do not commit dumps, protected JARs, keys, or
customer data to this repository.

## License

MIT — see [LICENSE](LICENSE).

Maintained by **sp1cy** · [0x1q2s](https://github.com/0x1q2s) · [sp1cy.dev](https://sp1cy.dev)
