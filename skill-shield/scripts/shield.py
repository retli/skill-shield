#!/usr/bin/env python3
"""
Skill Shield — Universal Skill Security Scanner & Auditor
安装前扫描 + 安装后审计，适配所有主流 AI Agent 平台。

用法:
    python3 shield.py scan <path-or-url>         扫描某个 skill 目录或远程 URL
    python3 shield.py audit [--workspace <dir>]  审计所有已安装的 skills
    python3 shield.py check-url <url>            检查 URL 是否在白名单中

退出码:
    0 = 安全或低风险
    1 = 高风险 (需确认)
    2 = 极高风险 (建议拒绝)
"""

import os
import sys
import re
import json
import platform
from pathlib import Path

# ─── 风险等级 ──────────────────────────────────────────────
CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
LEVELS = [CRITICAL, HIGH, MEDIUM, LOW]

# ─── 路径配置 ──────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent.parent
PATTERNS_DIR = SCRIPT_DIR / "patterns"


def discover_skill_paths(workspace_dir=None):
    """
    自动发现所有可能存放 Skills 的路径。
    覆盖全局 (HOME)、工作区 (workspace)、项目 (cwd) 三个维度，
    并适配所有已知的 AI Agent 平台目录结构。
    """
    home = Path.home()
    cwd = Path.cwd()
    candidates = []

    # ─── 1. 全局路径 (用户 HOME 下) ──────────────────────
    global_prefixes = [
        # Gemini Code Assist / Google AI
        ".gemini",
        # Claude Code / Anthropic
        ".claude",
        # Generic agent standards (OpenClaw etc.)
        ".agents", ".agent",
        # GitHub Copilot
        ".copilot",
        # Cursor
        ".cursor",
        # Windsurf / Codeium
        ".windsurf", ".codeium",
        # Continue.dev
        ".continue",
        # Aider
        ".aider",
    ]
    for prefix in global_prefixes:
        candidates.append(home / prefix / "skills")

    # ─── 2. 工作区路径 (项目根目录下) ────────────────────
    workspace_roots = [cwd]
    if workspace_dir:
        workspace_roots.append(Path(workspace_dir))

    workspace_skill_dirs = [
        # 标准 skills 子目录
        "skills",
        # .agents / .agent / _agents / _agent 规范
        ".agents/skills", ".agent/skills",
        "_agents/skills", "_agent/skills",
        # .gemini / .claude 项目级配置
        ".gemini/skills", ".claude/skills",
        # .github 下的 skills
        ".github/skills",
        # .cursor 项目级
        ".cursor/skills",
    ]
    for root in workspace_roots:
        for subdir in workspace_skill_dirs:
            candidates.append(root / subdir)

    # ─── 3. 去重并过滤存在的路径 ─────────────────────────
    seen = set()
    valid = []
    for p in candidates:
        resolved = p.resolve()
        if resolved not in seen and resolved.exists() and resolved.is_dir():
            seen.add(resolved)
            valid.append(resolved)

    return valid


# ─── 模式加载 ─────────────────────────────────────────────
def load_patterns():
    patterns = {}
    for level in LEVELS:
        pf = PATTERNS_DIR / f"{level}.json"
        if pf.exists():
            with open(pf, "r", encoding="utf-8") as f:
                patterns[level] = json.load(f).get("patterns", [])
        else:
            patterns[level] = []
    return patterns


def load_allowlist():
    af = PATTERNS_DIR / "allowlist.json"
    if af.exists():
        with open(af, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"urls": [], "npm_packages": [], "pip_packages": []}


PATTERNS = load_patterns()
ALLOWLIST = load_allowlist()


def is_allowlisted(value, key):
    for pat in ALLOWLIST.get(key, []):
        if re.search(pat, value, re.IGNORECASE):
            return True
    return False


# ─── 扫描引擎 ─────────────────────────────────────────────
SCAN_EXTENSIONS = {".md", ".sh", ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml"}


def scan_content(content, filename=""):
    findings = {l: [] for l in LEVELS}
    for line_num, line in enumerate(content.split("\n"), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for risk_level, pats in PATTERNS.items():
            for p in pats:
                try:
                    for m in re.finditer(p["pattern"], line, re.IGNORECASE):
                        matched = m.group(0)
                        if "check_allowlist" in p and is_allowlisted(matched, p["check_allowlist"]):
                            continue
                        findings[risk_level].append({
                            "file": filename,
                            "line": line_num,
                            "pattern": p["name"],
                            "matched": matched[:100],
                            "description": p["description"],
                            "context": stripped[:150],
                        })
                except re.error:
                    continue
    return findings


def scan_directory(path):
    all_f = {l: [] for l in LEVELS}
    path = Path(path)
    if not path.exists():
        return all_f
    for fp in path.rglob("*"):
        if fp.suffix.lower() in SCAN_EXTENSIONS:
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
                fds = scan_content(content, str(fp.relative_to(path)))
                for lv in all_f:
                    all_f[lv].extend(fds[lv])
            except Exception:
                continue
    return all_f


# ─── 报告输出 ─────────────────────────────────────────────
RISK_ICON = {"critical": "🔴", "high": "🟡", "medium": "🟠", "low": "🟢"}
RISK_LABEL = {
    CRITICAL: "🔴 CRITICAL — Reject / Uninstall immediately",
    HIGH:     "🟡 HIGH — Manual review required",
    MEDIUM:   "🟠 MEDIUM — Informational, verify URLs/commands",
    LOW:      "🟢 LOW — Generally safe",
    "safe":   "✅ SAFE — No suspicious patterns found",
}


def get_risk(findings):
    for lv in LEVELS:
        if findings[lv]:
            return lv
    return "safe"


def exit_code_for(risk):
    return {CRITICAL: 2, HIGH: 1}.get(risk, 0)


def print_report(findings, source):
    risk = get_risk(findings)
    total = sum(len(findings[l]) for l in LEVELS)

    print(f"\n[🛡️ Skill Shield] Scanning: {source}")
    print("=" * 60)
    print(f"Risk: {RISK_LABEL[risk]}")

    if total > 0:
        print(f"\n{total} finding(s):\n")
        for lv in LEVELS:
            if findings[lv]:
                print(f"  {RISK_ICON[lv]} {lv.upper()} ({len(findings[lv])})")
                for item in findings[lv]:
                    print(f"    ├─ {item['file']}:{item['line']} | {item['description']}")
                    print(f"    │  └─ {item['matched']}")
                print()
    print("=" * 60)
    return risk


def print_summary_line(name, risk):
    icon = "✅" if risk == "safe" else RISK_ICON.get(risk, "?")
    print(f"  {icon} {name.ljust(35)} {risk.upper()}")


# ─── 远程获取 ─────────────────────────────────────────────
def fetch_remote(url):
    from urllib.request import urlopen, Request
    if "github.com" in url:
        if "/blob/" in url:
            url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        elif "/tree/" in url:
            print("Tip: For GitHub directories, clone locally first then scan.")
            return None
    try:
        req = Request(url, headers={"User-Agent": "skill-shield/2.0"})
        with urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except Exception as e:
        print(f"Failed to fetch: {e}")
        return None


# ─── 命令: scan ──────────────────────────────────────────
def cmd_scan(target):
    if target.startswith("http"):
        content = fetch_remote(target)
        if not content:
            sys.exit(1)
        findings = scan_content(content, target)
    else:
        p = Path(target)
        if p.is_file():
            findings = scan_content(p.read_text(errors="ignore"), p.name)
        else:
            findings = scan_directory(p)
    risk = print_report(findings, target)
    sys.exit(exit_code_for(risk))


# ─── 命令: audit ─────────────────────────────────────────
def cmd_audit(workspace_dir=None):
    paths = discover_skill_paths(workspace_dir)

    print("\n[🛡️ Skill Shield] Full System Audit")
    print("=" * 60)
    print(f"OS: {platform.system()} {platform.release()}")
    print(f"Discovered {len(paths)} skill location(s):\n")
    for p in paths:
        print(f"  📂 {p}")
    print()

    worst_exit = 0
    total_skills = 0
    risky_skills = []

    for base in paths:
        print(f"─── {base} ───")
        entries = sorted(base.iterdir())
        skill_dirs = [d for d in entries if d.is_dir() and not d.name.startswith(".")]
        if not skill_dirs:
            print("  (empty)")
            continue

        for sd in skill_dirs:
            total_skills += 1
            findings = scan_directory(sd)
            risk = get_risk(findings)

            if risk in [CRITICAL, HIGH]:
                risky_skills.append((sd.name, risk, base))
                print_report(findings, f"{sd.name} (@ {base})")
            else:
                print_summary_line(sd.name, risk)

            worst_exit = max(worst_exit, exit_code_for(risk))
        print()

    # ─── 总结 ────────────────────────────────────────────
    print("=" * 60)
    print(f"[Summary] Scanned {total_skills} skill(s) across {len(paths)} location(s).")
    if risky_skills:
        print(f"\n⚠️  {len(risky_skills)} skill(s) require attention:")
        for name, risk, base in risky_skills:
            print(f"  {RISK_ICON[risk]} {name} ({risk.upper()}) @ {base}")
    else:
        print("\n✅ All skills passed. No critical or high-risk issues found.")
    print("=" * 60)
    sys.exit(worst_exit)


# ─── 命令: check-url ─────────────────────────────────────
def cmd_check_url(url):
    if is_allowlisted(url, "urls"):
        print(f"✅ Allowlisted: {url}")
    else:
        print(f"⚠️  NOT in allowlist: {url}")


# ─── 入口 ────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "scan":
        if len(sys.argv) < 3:
            print("Usage: shield.py scan <path-or-url>")
            sys.exit(1)
        cmd_scan(sys.argv[2])

    elif cmd == "audit":
        ws = None
        if "--workspace" in sys.argv:
            idx = sys.argv.index("--workspace")
            if idx + 1 < len(sys.argv):
                ws = sys.argv[idx + 1]
        cmd_audit(ws)

    elif cmd == "check-url":
        if len(sys.argv) < 3:
            print("Usage: shield.py check-url <url>")
            sys.exit(1)
        cmd_check_url(sys.argv[2])

    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
