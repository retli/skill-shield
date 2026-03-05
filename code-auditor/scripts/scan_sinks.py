#!/usr/bin/env python3
"""
scan_sinks.py — Code Auditor Sink Pre-Scanner

Zero-dependency Python script for automated sink detection and EALOC tiering.
Scans source files for dangerous function calls and classifies them by
EALOC tier (entry/business/model layer).

Supports: Java, Python, Go, PHP, JavaScript/Node.js, C#, C/C++, Ruby, Rust

Usage:
    python3 scan_sinks.py <target_directory_or_file> [--json]
"""

import sys
import os
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Tuple
from enum import Enum
from collections import defaultdict


# ─── Configuration ───────────────────────────────────────────────

MAX_FILE_SIZE = 1_048_576  # 1 MB

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", "target",
    "bin", "obj", ".next", ".nuxt", ".svelte-kit", "vendor", "packages",
    ".idea", ".vscode", ".gradle", ".mvn",
}

# Language detection by file extension
LANG_EXTENSIONS: Dict[str, List[str]] = {
    "java":       [".java"],
    "python":     [".py"],
    "go":         [".go"],
    "php":        [".php"],
    "javascript": [".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"],
    "csharp":     [".cs"],
    "c_cpp":      [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"],
    "ruby":       [".rb"],
    "rust":       [".rs"],
}

EXT_TO_LANG = {}
for lang, exts in LANG_EXTENSIONS.items():
    for ext in exts:
        EXT_TO_LANG[ext] = lang


# ─── EALOC Tier Classification ──────────────────────────────────

class Tier(Enum):
    T1 = "Tier1-Entry"
    T2 = "Tier2-Business"
    T3 = "Tier3-Model"

TIER_WEIGHTS = {Tier.T1: 1.0, Tier.T2: 0.5, Tier.T3: 0.1}

# Patterns to classify files by tier (case-insensitive matching on filename/path)
TIER_PATTERNS: Dict[str, Dict[Tier, List[str]]] = {
    "java": {
        Tier.T1: ["controller", "filter", "interceptor", "handler", "servlet", "endpoint", "resource", "rest"],
        Tier.T2: ["service", "dao", "mapper", "repository", "manager", "provider", "facade", "impl"],
        Tier.T3: ["entity", "dto", "vo", "pojo", "model", "config", "bean", "constant"],
    },
    "python": {
        Tier.T1: ["view", "route", "api", "endpoint", "handler", "middleware", "webhook"],
        Tier.T2: ["service", "manager", "model", "task", "worker", "util", "helper"],
        Tier.T3: ["serializer", "schema", "config", "setting", "constant", "enum", "form"],
    },
    "go": {
        Tier.T1: ["handler", "router", "middleware", "server", "api", "endpoint", "controller"],
        Tier.T2: ["service", "repo", "repository", "store", "usecase", "worker"],
        Tier.T3: ["model", "entity", "config", "types", "constant", "enum"],
    },
    "php": {
        Tier.T1: ["controller", "middleware", "handler", "route", "api", "action"],
        Tier.T2: ["service", "repository", "model", "manager", "provider", "job"],
        Tier.T3: ["entity", "request", "resource", "config", "migration", "seeder"],
    },
    "javascript": {
        Tier.T1: ["controller", "router", "route", "middleware", "handler", "api", "endpoint"],
        Tier.T2: ["service", "model", "repository", "store", "worker", "util", "helper"],
        Tier.T3: ["dto", "entity", "config", "constant", "type", "interface", "schema"],
    },
    "csharp": {
        Tier.T1: ["controller", "middleware", "filter", "handler", "hub", "endpoint"],
        Tier.T2: ["service", "repository", "manager", "provider", "worker"],
        Tier.T3: ["entity", "dto", "model", "config", "viewmodel", "request", "response"],
    },
    "c_cpp": {
        Tier.T1: ["main", "server", "handler", "daemon", "listener"],
        Tier.T2: ["util", "lib", "helper", "parser", "protocol", "auth"],
        Tier.T3: ["types", "config", "constant", "struct", "enum", "define"],
    },
    "ruby": {
        Tier.T1: ["controller", "middleware", "route", "api", "endpoint", "action"],
        Tier.T2: ["model", "service", "worker", "job", "mailer", "helper"],
        Tier.T3: ["serializer", "config", "initializer", "migration", "decorator"],
    },
    "rust": {
        Tier.T1: ["handler", "router", "server", "middleware", "api", "endpoint"],
        Tier.T2: ["service", "repo", "repository", "worker", "util"],
        Tier.T3: ["model", "entity", "config", "types", "schema", "error"],
    },
}


# ─── Sink Patterns ──────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"

@dataclass
class SinkPattern:
    name: str
    regex: str
    severity: Severity
    description: str
    compiled: re.Pattern = field(init=False, repr=False)

    def __post_init__(self):
        try:
            self.compiled = re.compile(self.regex, re.IGNORECASE)
        except re.error:
            self.compiled = None

@dataclass
class Finding:
    file_path: str
    line_number: int
    sink_type: str
    severity: Severity
    tier: Tier
    language: str
    matched_text: str
    description: str

# Universal patterns (apply to most languages)
UNIVERSAL_SINKS = [
    SinkPattern("hardcoded_password", r"""(?:password|passwd|pwd)\s*[=:]\s*['""][^'"]{8,}['"]""", Severity.HIGH, "Hardcoded password detected"),
    SinkPattern("private_key", r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", Severity.CRITICAL, "Private key in source code"),
    SinkPattern("aws_access_key", r"AKIA[0-9A-Z]{16}", Severity.CRITICAL, "AWS access key ID"),
    SinkPattern("generic_api_key", r"""(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[=:]\s*['""][a-zA-Z0-9_\-]{20,}['"]""", Severity.HIGH, "Potential API key or token"),
    SinkPattern("connection_string", r"(?:postgres|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:]+:[^@]+@[^\s\"']+", Severity.CRITICAL, "Database connection string with credentials"),
]

# Language-specific sink patterns
LANG_SINKS: Dict[str, List[SinkPattern]] = {
    "java": [
        SinkPattern("sql_concat", r"""(?:execute|executeQuery|executeUpdate|createQuery|createNativeQuery)\s*\(.*\+""", Severity.CRITICAL, "SQL string concatenation"),
        SinkPattern("mybatis_dollar", r"""\$\{[^}]+\}""", Severity.CRITICAL, "MyBatis ${} injection point"),
        SinkPattern("runtime_exec", r"""Runtime\.getRuntime\(\)\s*\.\s*exec\s*\(""", Severity.CRITICAL, "Runtime.exec() command execution"),
        SinkPattern("process_builder", r"""new\s+ProcessBuilder\s*\(""", Severity.HIGH, "ProcessBuilder command execution"),
        SinkPattern("deserialization", r"""(?:ObjectInputStream|readObject|readUnshared|XMLDecoder)\s*[\(.]""", Severity.CRITICAL, "Deserialization sink"),
        SinkPattern("jndi_lookup", r"""\.lookup\s*\(""", Severity.CRITICAL, "JNDI lookup (potential injection)"),
        SinkPattern("xxe_parser", r"""(?:DocumentBuilder|SAXParser|SAXReader|SAXBuilder|XMLInputFactory)""", Severity.HIGH, "XML parser (potential XXE)"),
        SinkPattern("spel_expression", r"""SpelExpressionParser|parseExpression""", Severity.HIGH, "SpEL expression (potential RCE)"),
        SinkPattern("ssrf_http", r"""(?:RestTemplate|HttpClient|OkHttpClient|WebClient|URL\s*\()""", Severity.MEDIUM, "HTTP client (potential SSRF)"),
        SinkPattern("file_operation", r"""new\s+File\s*\([^)]*\+|FileInputStream\s*\([^)]*\+|Paths\.get\s*\([^)]*\+""", Severity.HIGH, "File operation with concatenation"),
        SinkPattern("fastjson", r"""JSON\.parse(?:Object|Array)?\s*\(""", Severity.HIGH, "Fastjson deserialization"),
    ],
    "python": [
        SinkPattern("eval_exec", r"""\b(?:eval|exec)\s*\(""", Severity.CRITICAL, "eval()/exec() code execution"),
        SinkPattern("os_system", r"""os\.(?:system|popen)\s*\(""", Severity.CRITICAL, "os.system/popen command execution"),
        SinkPattern("subprocess_shell", r"""subprocess\.(?:call|run|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\(.*shell\s*=\s*True""", Severity.CRITICAL, "subprocess with shell=True"),
        SinkPattern("subprocess_concat", r"""subprocess\.(?:call|run|Popen|check_output|check_call|getoutput)\s*\([^)]*(?:\+|%|\.format|f['\"])""", Severity.CRITICAL, "subprocess with string concatenation"),
        SinkPattern("pickle_load", r"""pickle\.(?:loads?|Unpickler)\s*\(""", Severity.CRITICAL, "Pickle deserialization RCE"),
        SinkPattern("yaml_unsafe", r"""yaml\.(?:load|full_load)\s*\((?!.*SafeLoader)""", Severity.HIGH, "yaml.load without SafeLoader"),
        SinkPattern("sql_concat", r"""(?:execute|executemany|cursor\.execute)\s*\([^)]*\+""", Severity.CRITICAL, "SQL string concatenation"),
        SinkPattern("sql_format", r"""(?:execute|executemany)\s*\([^)]*(?:%s|%d|\.format|\bf['\"])""", Severity.CRITICAL, "SQL with string formatting"),
        SinkPattern("django_raw", r"""\.raw\s*\(.*(?:\+|%|\.format|f['\"])""", Severity.CRITICAL, "Django raw SQL with formatting"),
        SinkPattern("ssti", r"""render_template_string\s*\(|Template\s*\([^)]*\)\.render""", Severity.CRITICAL, "SSTI template injection"),
        SinkPattern("ssrf_requests", r"""requests\.(?:get|post|put|delete|patch|head)\s*\(""", Severity.HIGH, "HTTP request (potential SSRF)"),
        SinkPattern("ssrf_urllib", r"""urllib\.request\.(?:urlopen|Request)\s*\(""", Severity.HIGH, "urllib request (potential SSRF)"),
        SinkPattern("path_traversal", r"""(?:send_file|send_from_directory|FileResponse|open)\s*\([^)]*(?:\+|%|\.format|f['\"])""", Severity.HIGH, "Path traversal via concatenation"),
        SinkPattern("file_open", r"""open\s*\([^)]*(?:request\.|user|input|param)""", Severity.HIGH, "File open with user input"),
        SinkPattern("debug_mode", r"""(?:app\.run|DEBUG)\s*\(.*debug\s*=\s*True|DEBUG\s*=\s*True""", Severity.MEDIUM, "Debug mode enabled"),
    ],
    "go": [
        SinkPattern("sql_sprintf", r"""(?:db\.(?:Query|Exec|QueryRow)|Sprintf).*(?:\+|fmt\.Sprintf)""", Severity.CRITICAL, "SQL string formatting"),
        SinkPattern("os_exec", r"""exec\.Command\s*\(""", Severity.HIGH, "exec.Command execution"),
        SinkPattern("template_html", r"""template\.HTML\s*\(""", Severity.HIGH, "Unescaped HTML template"),
        SinkPattern("ssrf", r"""http\.(?:Get|Post|NewRequest)\s*\(""", Severity.MEDIUM, "HTTP request (potential SSRF)"),
        SinkPattern("file_path", r"""os\.Open\s*\([^)]*\+|filepath\.Join\s*\([^)]*(?:param|input|query)""", Severity.HIGH, "File path with user input"),
        SinkPattern("race_condition", r"""go\s+func\s*\(""", Severity.MEDIUM, "Goroutine (check race conditions)"),
        SinkPattern("deserialization", r"""(?:json|xml|gob)\.(?:Unmarshal|NewDecoder)""", Severity.MEDIUM, "Deserialization point"),
    ],
    "php": [
        SinkPattern("eval_system", r"""\b(?:eval|system|exec|passthru|shell_exec|popen)\s*\(""", Severity.CRITICAL, "Code/command execution"),
        SinkPattern("sql_concat", r"""(?:mysql_query|mysqli_query|->query)\s*\(.*(?:\.|\\$)""", Severity.CRITICAL, "SQL concatenation"),
        SinkPattern("file_include", r"""\b(?:include|require|include_once|require_once)\s*\(?\s*\$""", Severity.CRITICAL, "Dynamic file inclusion"),
        SinkPattern("unserialize", r"""\bunserialize\s*\(""", Severity.CRITICAL, "PHP unserialize RCE"),
        SinkPattern("file_operation", r"""\b(?:file_get_contents|file_put_contents|fopen|readfile)\s*\(\s*\$""", Severity.HIGH, "File operation with variable"),
        SinkPattern("preg_e_modifier", r"""preg_replace\s*\(\s*['\"]/.*/e""", Severity.CRITICAL, "preg_replace with /e modifier"),
        SinkPattern("ssrf", r"""\b(?:curl_exec|file_get_contents|fopen)\s*\(\s*\$""", Severity.HIGH, "Potential SSRF"),
    ],
    "javascript": [
        SinkPattern("eval", r"""\beval\s*\(""", Severity.CRITICAL, "eval() code execution"),
        SinkPattern("child_process", r"""child_process\.(?:exec|execSync|spawn)\s*\(""", Severity.CRITICAL, "child_process command execution"),
        SinkPattern("function_constructor", r"""\bFunction\s*\(""", Severity.HIGH, "Function() constructor execution"),
        SinkPattern("prototype_pollution", r"""__proto__|Object\.assign\s*\([^,]*,\s*(?:req|user|input|body)""", Severity.HIGH, "Potential prototype pollution"),
        SinkPattern("xss_innerhtml", r"""\.innerHTML\s*=|dangerouslySetInnerHTML""", Severity.HIGH, "Unescaped HTML assignment (XSS)"),
        SinkPattern("sql_template", r"""(?:query|execute)\s*\(.*(?:\$\{|` ?\+)""", Severity.CRITICAL, "SQL template literal injection"),
        SinkPattern("deserialization", r"""\b(?:deserialize|node-serialize)\s*\(""", Severity.CRITICAL, "Deserialization sink"),
        SinkPattern("path_traversal", r"""(?:readFile|createReadStream|unlink)\s*\([^)]*(?:req\.|user|param|query)""", Severity.HIGH, "File operation with user input"),
    ],
    "csharp": [
        SinkPattern("sql_concat", r"""(?:SqlCommand|ExecuteReader|ExecuteNonQuery|ExecuteScalar).*(?:\+|String\.Format|\$\")""", Severity.CRITICAL, "SQL concatenation"),
        SinkPattern("process_start", r"""Process\.Start\s*\(""", Severity.HIGH, "Process.Start execution"),
        SinkPattern("deserialization", r"""(?:BinaryFormatter|ObjectStateFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter)""", Severity.CRITICAL, "Unsafe deserialization"),
        SinkPattern("file_operation", r"""(?:File\.(?:ReadAllText|WriteAllText|Open|Delete)|StreamReader)\s*\([^)]*\+""", Severity.HIGH, "File operation with concatenation"),
        SinkPattern("xss", r"""@Html\.Raw\s*\(""", Severity.HIGH, "Html.Raw XSS risk"),
        SinkPattern("xpath_injection", r"""SelectNodes\s*\(.*\+|XPathNavigator""", Severity.HIGH, "XPath injection"),
    ],
    "c_cpp": [
        SinkPattern("system_exec", r"""\b(?:system|popen|exec[lv]?p?)\s*\(""", Severity.CRITICAL, "System/exec command execution"),
        SinkPattern("gets_buffer", r"""\bgets\s*\(""", Severity.CRITICAL, "gets() buffer overflow"),
        SinkPattern("strcpy_unsafe", r"""\b(?:strcpy|strcat|sprintf|vsprintf)\s*\(""", Severity.HIGH, "Unsafe string function (buffer overflow)"),
        SinkPattern("format_string", r"""(?:printf|fprintf|sprintf|snprintf)\s*\([^,]*(?:argv|user|input|buf)""", Severity.CRITICAL, "Format string vulnerability"),
        SinkPattern("malloc_no_check", r"""=\s*malloc\s*\([^)]+\)\s*;(?!\s*if)""", Severity.MEDIUM, "malloc without null check"),
        SinkPattern("use_after_free", r"""\bfree\s*\(\s*(\w+)\s*\)""", Severity.HIGH, "free() call (check use-after-free)"),
    ],
    "ruby": [
        SinkPattern("eval_exec", r"""\b(?:eval|exec|system|%x)\s*[\(\{]?""", Severity.CRITICAL, "Code/command execution"),
        SinkPattern("marshal_load", r"""Marshal\.(?:load|restore)\s*\(""", Severity.CRITICAL, "Marshal deserialization RCE"),
        SinkPattern("erb_render", r"""ERB\.new\s*\(""", Severity.HIGH, "ERB template injection"),
        SinkPattern("send_method", r"""\.send\s*\(.*(?:params|user|input)""", Severity.HIGH, "Dynamic method dispatch with user input"),
        SinkPattern("sql_interpolation", r"""(?:where|find_by_sql|execute)\s*\(?\s*["'].*#\{""", Severity.CRITICAL, "SQL string interpolation"),
        SinkPattern("open_uri", r"""(?:open|URI\.open|Net::HTTP)\s*\(.*(?:params|user|input)""", Severity.HIGH, "HTTP with user input (SSRF)"),
    ],
    "rust": [
        SinkPattern("unsafe_block", r"""\bunsafe\s*\{""", Severity.HIGH, "unsafe block (manual review required)"),
        SinkPattern("command_exec", r"""Command::new\s*\(""", Severity.HIGH, "Command execution"),
        SinkPattern("ffi_extern", r"""\bextern\s+\"C\"""", Severity.HIGH, "FFI boundary (check memory safety)"),
        SinkPattern("raw_pointer", r"""\*(?:const|mut)\s+""", Severity.MEDIUM, "Raw pointer usage"),
        SinkPattern("unwrap_expect", r"""\.unwrap\(\)|\.expect\(""", Severity.MEDIUM, "unwrap/expect (potential panic)"),
        SinkPattern("sql_format", r"""(?:query|execute).*format!\s*\(""", Severity.CRITICAL, "SQL with format! macro"),
    ],
}


# ─── Core Functions ─────────────────────────────────────────────

def classify_tier(file_path: Path, language: str) -> Tier:
    """Classify a file into EALOC tier based on filename/path patterns."""
    name_lower = file_path.stem.lower()
    path_lower = str(file_path).lower()

    patterns = TIER_PATTERNS.get(language, {})

    for tier in [Tier.T1, Tier.T2, Tier.T3]:
        for pattern in patterns.get(tier, []):
            if pattern in name_lower or pattern in path_lower:
                return tier

    return Tier.T2  # Default: business layer


def should_scan(file_path: Path) -> bool:
    """Check if file should be scanned."""
    if file_path.suffix.lower() not in EXT_TO_LANG:
        return False
    try:
        if file_path.stat().st_size > MAX_FILE_SIZE:
            return False
    except OSError:
        return False
    return True


def is_skip_dir(path: Path) -> bool:
    """Check if any parent dir should be skipped."""
    for part in path.parts:
        if part in SKIP_DIRS:
            return True
    return False


def scan_file(file_path: Path, language: str, tier: Tier) -> List[Finding]:
    """Scan a single file for sink patterns."""
    findings = []

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, OSError):
        return findings

    # Combine universal + language-specific patterns
    patterns = UNIVERSAL_SINKS + LANG_SINKS.get(language, [])

    for pattern in patterns:
        if pattern.compiled is None:
            continue
        for match in pattern.compiled.finditer(content):
            line_number = content[:match.start()].count("\n") + 1
            matched_text = match.group(0)
            if len(matched_text) > 120:
                matched_text = matched_text[:120] + "..."

            findings.append(Finding(
                file_path=str(file_path),
                line_number=line_number,
                sink_type=pattern.name,
                severity=pattern.severity,
                tier=tier,
                language=language,
                matched_text=matched_text,
                description=pattern.description,
            ))

    return findings


def scan_directory(target: Path) -> Tuple[List[Finding], Dict]:
    """Scan entire directory tree."""
    findings: List[Finding] = []
    stats = {
        "files_scanned": 0,
        "languages": defaultdict(int),
        "tiers": {Tier.T1: {"files": 0, "loc": 0}, Tier.T2: {"files": 0, "loc": 0}, Tier.T3: {"files": 0, "loc": 0}},
    }

    for file_path in target.rglob("*"):
        if not file_path.is_file():
            continue
        if is_skip_dir(file_path):
            continue
        if not should_scan(file_path):
            continue

        language = EXT_TO_LANG.get(file_path.suffix.lower())
        if not language:
            continue

        tier = classify_tier(file_path, language)

        try:
            loc = file_path.read_text(encoding="utf-8", errors="replace").count("\n") + 1
        except (PermissionError, OSError):
            loc = 0

        stats["files_scanned"] += 1
        stats["languages"][language] += 1
        stats["tiers"][tier]["files"] += 1
        stats["tiers"][tier]["loc"] += loc

        file_findings = scan_file(file_path, language, tier)
        findings.extend(file_findings)

    return findings, stats


def format_report(findings: List[Finding], stats: Dict, target: str) -> str:
    """Generate formatted text report."""
    lines = []
    lines.append("=" * 70)
    lines.append("  Code Auditor — Sink Pre-Scan Report")
    lines.append("=" * 70)
    lines.append(f"\n  Target: {target}")
    lines.append(f"  Files scanned: {stats['files_scanned']}")

    # Language distribution
    if stats["languages"]:
        lang_str = ", ".join(f"{k}: {v}" for k, v in sorted(stats["languages"].items(), key=lambda x: -x[1]))
        lines.append(f"  Languages: {lang_str}")

    # EALOC
    lines.append("\n[EALOC Distribution]")
    t1 = stats["tiers"][Tier.T1]
    t2 = stats["tiers"][Tier.T2]
    t3 = stats["tiers"][Tier.T3]
    lines.append(f"  Tier1 (Entry):    {t1['files']:>4} files, {t1['loc']:>6} LOC  ← ×1.0")
    lines.append(f"  Tier2 (Business): {t2['files']:>4} files, {t2['loc']:>6} LOC  ← ×0.5")
    lines.append(f"  Tier3 (Model):    {t3['files']:>4} files, {t3['loc']:>6} LOC  ← ×0.1")
    ealoc = t1["loc"] * 1.0 + t2["loc"] * 0.5 + t3["loc"] * 0.1
    lines.append(f"  EALOC = {t1['loc']}×1.0 + {t2['loc']}×0.5 + {t3['loc']}×0.1 = {ealoc:.0f} effective LOC")

    # Findings summary
    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.severity] += 1

    total = len(findings)
    lines.append(f"\n[Sink Scan Results]  Total: {total} findings")
    lines.append(f"  🔴 CRITICAL: {sev_counts[Severity.CRITICAL]}")
    lines.append(f"  🟡 HIGH:     {sev_counts[Severity.HIGH]}")
    lines.append(f"  🔵 MEDIUM:   {sev_counts[Severity.MEDIUM]}")

    if not findings:
        lines.append("\n  No sinks detected.")
        lines.append("=" * 70)
        return "\n".join(lines)

    # Group by severity
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
        sev_findings = [f for f in findings if f.severity == severity]
        if not sev_findings:
            continue

        color = {"CRITICAL": "🔴", "HIGH": "🟡", "MEDIUM": "🔵"}[severity.value]
        lines.append(f"\n--- {color} {severity.value} ({len(sev_findings)}) ---")

        for f in sev_findings:
            rel_path = os.path.relpath(f.file_path, target)
            tier_label = f.tier.value.split("-")[0]
            lines.append(f"  {rel_path}:{f.line_number}")
            lines.append(f"    [{f.sink_type}] {f.description}")
            lines.append(f"    Layer: {tier_label} | Match: {f.matched_text}")
            lines.append("")

    # Top files by sink density
    file_counts = defaultdict(int)
    for f in findings:
        file_counts[f.file_path] += 1
    top_files = sorted(file_counts.items(), key=lambda x: -x[1])[:10]
    if top_files:
        lines.append("[Top Files by Sink Density]")
        for fp, count in top_files:
            rel = os.path.relpath(fp, target)
            tier = next((f.tier for f in findings if f.file_path == fp), Tier.T2)
            lines.append(f"  {count:>3} sinks | {tier.value.split('-')[0]} | {rel}")

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)


# ─── Single File Scan ────────────────────────────────────────────

def scan_single_file(file_path: Path):
    """Scan a single file and return findings + stats."""
    findings = []
    stats = {
        "files_scanned": 0,
        "languages": defaultdict(int),
        "tiers": {Tier.T1: {"files": 0, "loc": 0}, Tier.T2: {"files": 0, "loc": 0}, Tier.T3: {"files": 0, "loc": 0}},
    }

    language = EXT_TO_LANG.get(file_path.suffix.lower())
    if not language:
        return findings, stats

    tier = classify_tier(file_path, language)
    try:
        loc = file_path.read_text(encoding="utf-8", errors="replace").count("\n") + 1
    except (PermissionError, OSError):
        loc = 0

    stats["files_scanned"] = 1
    stats["languages"][language] = 1
    stats["tiers"][tier]["files"] = 1
    stats["tiers"][tier]["loc"] = loc

    findings = scan_file(file_path, language, tier)
    return findings, stats


# ─── Main ───────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        print("Arguments:")
        print("  <target_directory_or_file>  Path to the project or file to scan")
        print("  --json                      Output in JSON format (optional)")
        sys.exit(0)

    target = Path(sys.argv[1]).resolve()
    if not target.exists():
        print(f"Error: {target} does not exist", file=sys.stderr)
        sys.exit(1)

    use_json = "--json" in sys.argv

    if target.is_file():
        findings, stats = scan_single_file(target)
    else:
        findings, stats = scan_directory(target)

    if use_json:
        import json
        output = {
            "target": str(target),
            "stats": {
                "files_scanned": stats["files_scanned"],
                "languages": dict(stats["languages"]),
                "ealoc": {
                    "tier1": stats["tiers"][Tier.T1],
                    "tier2": stats["tiers"][Tier.T2],
                    "tier3": stats["tiers"][Tier.T3],
                },
            },
            "findings": [
                {
                    "file": f.file_path,
                    "line": f.line_number,
                    "sink_type": f.sink_type,
                    "severity": f.severity.value,
                    "tier": f.tier.value,
                    "language": f.language,
                    "match": f.matched_text,
                    "description": f.description,
                }
                for f in findings
            ],
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        print(format_report(findings, stats, str(target)))

    # Exit code: 1 if critical findings, 0 otherwise
    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    main()
