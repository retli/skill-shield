# 🛡️ Skill Shield

**Universal security scanner for AI agent skills.** Detects malicious patterns, supply-chain risks, and credential theft before and after skill installation.

## Why This Exists

In February 2026, security researchers discovered [malware distributed through agent skill marketplaces](https://1password.com/blog/from-magic-to-malware-how-openclaws-agent-skills-become-an-attack-surface). Skills can contain hidden install commands that download and execute malware, exfiltrate API keys, or escalate privileges. Skill Shield catches them.

## Features

- 🔍 **Pre-install scanning** — Scan a skill from a URL or local path before installing it
- 🔎 **Post-install auditing** — Scan ALL installed skills across ALL agent platforms at once
- 🌐 **Universal platform support** — Auto-discovers skills from Gemini, Claude, Copilot, Cursor, Windsurf, Continue, Aider, and more
- 📦 **Zero dependencies** — Uses only Python 3 standard library
- 🚦 **Exit-code driven** — `0` safe, `1` high-risk, `2` critical. Designed for CI/CD and automation

## Quick Start

```bash
# Scan a skill before installing
python3 scripts/shield.py scan /path/to/some-skill/

# Full system audit — scans all installed skills across all platforms
python3 scripts/shield.py audit

# Scan with explicit workspace
python3 scripts/shield.py audit --workspace /path/to/project
```

## Supported Platforms

Skill Shield auto-discovers skill directories for:

| Platform | Global Path | Workspace Path |
|----------|------------|----------------|
| Gemini Code Assist | `~/.gemini/skills` | `.gemini/skills` |
| Claude Code | `~/.claude/skills` | `.claude/skills` |
| OpenClaw / Generic | `~/.agents/skills`, `~/.agent/skills` | `.agents/skills`, `.agent/skills`, `_agents/skills`, `_agent/skills` |
| GitHub Copilot | `~/.copilot/skills` | `.github/skills` |
| Cursor | `~/.cursor/skills` | `.cursor/skills` |
| Windsurf / Codeium | `~/.windsurf/skills`, `~/.codeium/skills` | — |
| Continue.dev | `~/.continue/skills` | — |
| Aider | `~/.aider/skills` | — |

## Installation

Simply copy or clone the `skill-shield` directory into your agent's skill directory:

```bash
# For Gemini
cp -r skill-shield ~/.gemini/skills/

# For Claude
cp -r skill-shield ~/.claude/skills/

# For any agent using .agents convention
cp -r skill-shield ~/.agents/skills/
```

Once installed, the agent will automatically load `SKILL.md` and know when and how to run security scans.

## License

MIT
