"""
Security Analyzer - Détecte les vulnérabilités dans le code Python et JavaScript
"""

import re
import os
import json
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Vulnerability:
    id: str
    name: str
    severity: Severity
    category: str
    description: str
    line_number: int
    line_content: str
    file_path: str
    cwe: str
    recommendation: str
    test_template: str = ""


@dataclass
class AnalysisResult:
    file_path: str
    language: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    total_lines: int = 0
    scan_duration: float = 0.0

    def to_dict(self):
        return {
            "file_path": self.file_path,
            "language": self.language,
            "total_lines": self.total_lines,
            "scan_duration": self.scan_duration,
            "vulnerabilities": [
                {
                    "id": v.id,
                    "name": v.name,
                    "severity": v.severity.value,
                    "category": v.category,
                    "description": v.description,
                    "line_number": v.line_number,
                    "line_content": v.line_content.strip(),
                    "file_path": v.file_path,
                    "cwe": v.cwe,
                    "recommendation": v.recommendation,
                    "test_template": v.test_template,
                }
                for v in self.vulnerabilities
            ],
        }


# ─────────────────────────────────────────────
# RULES: Python vulnerabilities
# ─────────────────────────────────────────────
PYTHON_RULES = [
    {
        "id": "PY001",
        "name": "SQL Injection",
        "severity": Severity.CRITICAL,
        "category": "Injection",
        "pattern": r'(execute|cursor\.execute)\s*\(\s*["\'].*?\+|execute\s*\(\s*f["\'].*?\{',
        "description": "Concatenation of user input directly into SQL query.",
        "cwe": "CWE-89",
        "recommendation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        "test_template": "sql_injection",
    },
    {
        "id": "PY002",
        "name": "Hardcoded Secret / Credential",
        "severity": Severity.HIGH,
        "category": "Secret Exposure",
        "pattern": r'(?i)(password|secret|api_key|token|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
        "description": "Hardcoded credential or secret detected in source code.",
        "cwe": "CWE-798",
        "recommendation": "Use environment variables: os.environ.get('SECRET_KEY')",
        "test_template": "hardcoded_secret",
    },
    {
        "id": "PY003",
        "name": "Command Injection",
        "severity": Severity.CRITICAL,
        "category": "Injection",
        "pattern": r'(subprocess\.(run|call|Popen)|os\.system)\s*\(.*shell\s*=\s*True',
        "description": "User-controlled input passed to shell command.",
        "cwe": "CWE-78",
        "recommendation": "Use shell=False and pass arguments as a list: subprocess.run(['ping', host])",
        "test_template": "command_injection",
    },
    {
        "id": "PY004",
        "name": "Weak Hashing Algorithm (MD5/SHA1)",
        "severity": Severity.HIGH,
        "category": "Cryptography",
        "pattern": r'hashlib\.(md5|sha1)\s*\(',
        "description": "MD5 and SHA1 are cryptographically broken for password hashing.",
        "cwe": "CWE-328",
        "recommendation": "Use bcrypt, argon2, or hashlib.sha256 with salt.",
        "test_template": "weak_hash",
    },
    {
        "id": "PY005",
        "name": "Path Traversal",
        "severity": Severity.HIGH,
        "category": "File Access",
        "pattern": r'open\s*\(\s*[\w\s]*\+|open\s*\(\s*f["\']',
        "description": "File path constructed from user input without validation.",
        "cwe": "CWE-22",
        "recommendation": "Use os.path.abspath() and verify the path starts with the allowed base directory.",
        "test_template": "path_traversal",
    },
    {
        "id": "PY006",
        "name": "Insecure Deserialization (pickle)",
        "severity": Severity.CRITICAL,
        "category": "Deserialization",
        "pattern": r'pickle\.(loads|load)\s*\(',
        "description": "Deserializing untrusted data with pickle can lead to RCE.",
        "cwe": "CWE-502",
        "recommendation": "Use json.loads() for data exchange. Never unpickle untrusted data.",
        "test_template": "insecure_deserialization",
    },
    {
        "id": "PY007",
        "name": "Insecure Random Number Generation",
        "severity": Severity.MEDIUM,
        "category": "Cryptography",
        "pattern": r'random\.(randint|random|choice|randrange)\s*\(',
        "description": "random module is not cryptographically secure for tokens/secrets.",
        "cwe": "CWE-338",
        "recommendation": "Use secrets.token_hex() or secrets.token_urlsafe() for security tokens.",
        "test_template": "weak_random",
    },
    {
        "id": "PY008",
        "name": "XSS - Unescaped User Input in HTML",
        "severity": Severity.HIGH,
        "category": "XSS",
        "pattern": r'f["\'].*<.*?\{[\w_]+\}.*>["\']',
        "description": "User input embedded directly in HTML without escaping.",
        "cwe": "CWE-79",
        "recommendation": "Use html.escape() or a templating engine with auto-escaping (Jinja2).",
        "test_template": "xss",
    },
]

# ─────────────────────────────────────────────
# RULES: JavaScript vulnerabilities
# ─────────────────────────────────────────────
JS_RULES = [
    {
        "id": "JS001",
        "name": "SQL Injection",
        "severity": Severity.CRITICAL,
        "category": "Injection",
        "pattern": r'["\']SELECT.*WHERE.*["\'\s]\+\s*\w+|`SELECT.*\$\{',
        "description": "User input concatenated directly into SQL query string.",
        "cwe": "CWE-89",
        "recommendation": "Use parameterized queries or an ORM like Sequelize/Prisma.",
        "test_template": "sql_injection",
    },
    {
        "id": "JS002",
        "name": "Hardcoded Secret / Credential",
        "severity": Severity.HIGH,
        "category": "Secret Exposure",
        "pattern": r'(?i)(password|secret|api_?key|token)\s*=\s*["\'][^"\']{4,}["\']',
        "description": "Hardcoded credential or secret detected in source code.",
        "cwe": "CWE-798",
        "recommendation": "Use process.env.SECRET_KEY and a .env file (excluded from git).",
        "test_template": "hardcoded_secret",
    },
    {
        "id": "JS003",
        "name": "XSS - Unescaped Output",
        "severity": Severity.HIGH,
        "category": "XSS",
        "pattern": r'(innerHTML|outerHTML|document\.write)\s*=.*(\$\{|req\.(query|body|params))',
        "description": "User-controlled data written to DOM without sanitization.",
        "cwe": "CWE-79",
        "recommendation": "Use textContent instead of innerHTML, or sanitize with DOMPurify.",
        "test_template": "xss",
    },
    {
        "id": "JS004",
        "name": "Command Injection",
        "severity": Severity.CRITICAL,
        "category": "Injection",
        "pattern": r'exec\s*\(\s*`[^`]*\$\{|exec\s*\(\s*["\'].*?\+',
        "description": "User input passed to exec() without sanitization.",
        "cwe": "CWE-78",
        "recommendation": "Use execFile() with argument array. Never concatenate user input in shell commands.",
        "test_template": "command_injection",
    },
    {
        "id": "JS005",
        "name": "Dangerous eval() Usage",
        "severity": Severity.CRITICAL,
        "category": "Code Injection",
        "pattern": r'\beval\s*\(',
        "description": "eval() executes arbitrary code and is extremely dangerous.",
        "cwe": "CWE-95",
        "recommendation": "Never use eval(). Use JSON.parse() for data or Function() as last resort.",
        "test_template": "eval_injection",
    },
    {
        "id": "JS006",
        "name": "Insecure Random Number Generation",
        "severity": Severity.MEDIUM,
        "category": "Cryptography",
        "pattern": r'Math\.random\s*\(',
        "description": "Math.random() is not cryptographically secure.",
        "cwe": "CWE-338",
        "recommendation": "Use crypto.randomBytes() or crypto.getRandomValues() for security tokens.",
        "test_template": "weak_random",
    },
    {
        "id": "JS007",
        "name": "Path Traversal",
        "severity": Severity.HIGH,
        "category": "File Access",
        "pattern": r'(sendFile|readFile|readFileSync)\s*\(.*(\+|\$\{).*\)',
        "description": "File path constructed from user input without validation.",
        "cwe": "CWE-22",
        "recommendation": "Use path.resolve() and verify the result starts with the allowed base directory.",
        "test_template": "path_traversal",
    },
    {
        "id": "JS008",
        "name": "Prototype Pollution",
        "severity": Severity.HIGH,
        "category": "Object Injection",
        "pattern": r'for\s*\(\s*(let|var|const)\s+\w+\s+in\s+\w+\s*\)(?!.*hasOwnProperty)',
        "description": "Object property assignment without hasOwnProperty check can lead to prototype pollution.",
        "cwe": "CWE-1321",
        "recommendation": "Always check hasOwnProperty() or use Object.hasOwn() when merging objects.",
        "test_template": "prototype_pollution",
    },
]


class SecurityAnalyzer:
    def __init__(self):
        self.rules = {"python": PYTHON_RULES, "javascript": JS_RULES}

    def detect_language(self, file_path: str) -> Optional[str]:
        ext = os.path.splitext(file_path)[1].lower()
        return {"py": "python", ".py": "python", ".js": "javascript", "js": "javascript"}.get(ext)

    def analyze_file(self, file_path: str) -> AnalysisResult:
        import time

        language = self.detect_language(file_path)
        if not language:
            raise ValueError(f"Unsupported file type: {file_path}")

        start = time.time()
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        result = AnalysisResult(
            file_path=file_path,
            language=language,
            total_lines=len(lines),
        )

        rules = self.rules.get(language, [])
        vuln_counter = {}

        for line_num, line in enumerate(lines, start=1):
            for rule in rules:
                if re.search(rule["pattern"], line, re.IGNORECASE):
                    vuln_id = rule["id"]
                    vuln_counter[vuln_id] = vuln_counter.get(vuln_id, 0) + 1
                    unique_id = f"{vuln_id}-L{line_num}"
                    vuln = Vulnerability(
                        id=unique_id,
                        name=rule["name"],
                        severity=rule["severity"],
                        category=rule["category"],
                        description=rule["description"],
                        line_number=line_num,
                        line_content=line,
                        file_path=file_path,
                        cwe=rule["cwe"],
                        recommendation=rule["recommendation"],
                        test_template=rule["test_template"],
                    )
                    result.vulnerabilities.append(vuln)

        result.scan_duration = round(time.time() - start, 4)
        return result

    def analyze_directory(self, directory: str) -> List[AnalysisResult]:
        results = []
        for root, _, files in os.walk(directory):
            for fname in files:
                if fname.endswith((".py", ".js")):
                    fpath = os.path.join(root, fname)
                    try:
                        results.append(self.analyze_file(fpath))
                    except Exception as e:
                        print(f"[WARN] Could not analyze {fpath}: {e}")
        return results


if __name__ == "__main__":
    analyzer = SecurityAnalyzer()
    results = analyzer.analyze_directory("sample_app")
    for r in results:
        print(json.dumps(r.to_dict(), indent=2))
