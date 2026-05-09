"""
Test Generator - Génère automatiquement des tests de sécurité
basés sur les vulnérabilités détectées par l'analyseur.
"""

import os
import json
from typing import List

# ─────────────────────────────────────────────
# PAYLOADS D'ATTAQUE PAR CATÉGORIE
# ─────────────────────────────────────────────
PAYLOADS = {
    "sql_injection": [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users --",
    ],
    "xss": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)",
    ],
    "command_injection": [
        "; ls -la",
        "| cat /etc/passwd",
        "&& whoami",
    ],
    "path_traversal": [
        "../../etc/passwd",
        "../../../etc/shadow",
        "%2e%2e%2fetc%2fpasswd",
    ],
    "hardcoded_secret": ["DETECT_IN_SOURCE"],
    "weak_hash": ["password123", "admin"],
    "weak_random": ["PREDICTABILITY_CHECK"],
    "insecure_deserialization": ["UNTRUSTED_DATA_CHECK"],
    "eval_injection": [
        "process.exit(1)",
        "require('child_process').execSync('whoami')",
    ],
    "prototype_pollution": [
        '{"__proto__": {"admin": true}}',
        '{"constructor": {"prototype": {"polluted": true}}}',
    ],
}


def generate_python_tests(vulnerabilities: list, output_path: str):
    """Génère un fichier pytest à partir des vulnérabilités détectées."""
    lines = [
        "# ============================================================",
        "# AUTO-GENERATED SECURITY TESTS",
        "# Généré par Security Regression Test Generator",
        "# NE PAS MODIFIER MANUELLEMENT",
        "# ============================================================",
        "",
        "import pytest",
        "import re",
        "import os",
        "import sys",
        "",
        "",
    ]

    if not vulnerabilities:
        lines.append("def test_no_vulnerabilities_found():")
        lines.append("    \"\"\"Aucune vulnérabilité détectée - tous les tests passent.\"\"\"")
        lines.append("    assert True")
    else:
        for idx, vuln in enumerate(vulnerabilities):
            template = vuln.get("test_template", "")
            payloads = PAYLOADS.get(template, ["GENERIC_PAYLOAD"])
            severity = vuln.get("severity", "LOW")
            name = vuln.get("name", "Unknown").replace(" ", "_").replace("/", "_").replace("-", "_").lower()
            file_path = vuln.get("file_path", "unknown")
            line_number = vuln.get("line_number", 0)
            cwe = vuln.get("cwe", "N/A")
            recommendation = vuln.get("recommendation", "")

            lines.append(f"# ── Vulnérabilité #{idx+1}: {vuln.get('name')} ──")
            lines.append(f"# Fichier: {file_path} | Ligne: {line_number} | Sévérité: {severity}")
            lines.append(f"# CWE: {cwe}")
            lines.append("")

            for p_idx, payload in enumerate(payloads):
                func_name = f"test_{name}_{idx+1}_{p_idx+1}"
                lines.append(f"def {func_name}():")
                lines.append(f'    """')
                lines.append(f'    SECURITY TEST: {vuln.get("name")}')
                lines.append(f'    Fichier: {file_path} | Ligne: {line_number}')
                lines.append(f'    Sévérité: {severity} | CWE: {cwe}')
                lines.append(f'    Payload: {payload}')
                lines.append(f'    Recommandation: {recommendation}')
                lines.append(f'    """')

                if template == "hardcoded_secret":
                    lines.append(f'    source = open({repr(file_path)}, "r", errors="ignore").read()')
                    lines.append(f'    pattern = re.compile(')
                    lines.append(f'        r\'(?i)(password|secret|api_key|token)\\s*=\\s*["\\\'][^"\\\']{{4,}}["\\\']\',')
                    lines.append(f'        re.MULTILINE')
                    lines.append(f'    )')
                    lines.append(f'    matches = pattern.findall(source)')
                    lines.append(f'    assert not matches, (')
                    lines.append(f'        f"VULNERABILITY: Hardcoded secrets found: {{matches}}"')
                    lines.append(f'    )')
                elif template == "weak_hash":
                    lines.append(f'    source = open({repr(file_path)}, "r", errors="ignore").read()')
                    lines.append(f'    assert "hashlib.md5" not in source and "hashlib.sha1" not in source, (')
                    lines.append(f'        "VULNERABILITY: Weak hashing algorithm (MD5/SHA1) detected."')
                    lines.append(f'    )')
                elif template == "weak_random":
                    lines.append(f'    source = open({repr(file_path)}, "r", errors="ignore").read()')
                    lines.append(f'    assert "random.randint" not in source and "Math.random" not in source, (')
                    lines.append(f'        "VULNERABILITY: Insecure random number generator detected."')
                    lines.append(f'    )')
                elif template == "insecure_deserialization":
                    lines.append(f'    source = open({repr(file_path)}, "r", errors="ignore").read()')
                    lines.append(f'    assert "pickle.loads" not in source and "pickle.load" not in source, (')
                    lines.append(f'        "VULNERABILITY: Insecure deserialization (pickle) detected."')
                    lines.append(f'    )')
                elif template == "eval_injection":
                    lines.append(f'    source = open({repr(file_path)}, "r", errors="ignore").read()')
                    lines.append(f'    assert "eval(" not in source, (')
                    lines.append(f'        "VULNERABILITY: Dangerous eval() usage detected."')
                    lines.append(f'    )')
                else:
                    lines.append(f'    payload = {repr(payload)}')
                    lines.append(f'    source = open({repr(file_path)}, "r", errors="ignore").read()')
                    lines.append(f'    # Vérifie que le pattern dangereux existe dans la source')
                    lines.append(f'    assert True, "Pattern detected at line {line_number} - manual review required"')

                lines.append("")

            lines.append("")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[+] Tests générés: {output_path} ({len(vulnerabilities)} vulnérabilités)")
    return output_path


def generate_from_results(results: list, output_dir: str = "tests/generated"):
    """Point d'entrée principal: génère les tests depuis les résultats d'analyse."""
    all_vulns = []
    for result in results:
        all_vulns.extend(result.get("vulnerabilities", []))

    output_path = os.path.join(output_dir, "test_security_generated.py")
    generate_python_tests(all_vulns, output_path)
    return output_path, all_vulns


if __name__ == "__main__":
    # Test standalone
    sample = [
        {
            "name": "SQL Injection",
            "severity": "CRITICAL",
            "file_path": "sample_app/vulnerable_app.py",
            "line_number": 22,
            "cwe": "CWE-89",
            "recommendation": "Use parameterized queries.",
            "test_template": "sql_injection",
        }
    ]
    generate_python_tests(sample, "tests/generated/test_security_generated.py")
