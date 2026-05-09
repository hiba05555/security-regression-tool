"""
Security Runner - Orchestre l'analyse, la génération de tests et le rapport.
Point d'entrée principal du Security Regression Test Generator.
"""

import sys
import os
import json
import subprocess
import argparse
from datetime import datetime

# Ajoute le dossier racine au path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.security_analyzer import SecurityAnalyzer
from generator.test_generator import generate_from_results
from reporter.html_reporter import generate_html_report


def run_analysis(target: str):
    """Étape 1: Analyser le code."""
    print("\n" + "="*60)
    print("🔍 ÉTAPE 1/3 — ANALYSE DES VULNÉRABILITÉS")
    print("="*60)

    analyzer = SecurityAnalyzer()

    if os.path.isfile(target):
        results = [analyzer.analyze_file(target)]
    elif os.path.isdir(target):
        results = analyzer.analyze_directory(target)
    else:
        print(f"[ERROR] Cible introuvable: {target}")
        sys.exit(1)

    total_vulns = sum(len(r.vulnerabilities) for r in results)

    for result in results:
        count = len(result.vulnerabilities)
        print(f"  📄 {result.file_path} → {count} vulnérabilité(s) ({result.language})")
        for v in result.vulnerabilities:
            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}.get(v.severity.value, "⚪")
            print(f"     {sev_icon} [{v.severity.value}] {v.name} — Ligne {v.line_number} ({v.cwe})")

    print(f"\n  ✅ Analyse terminée: {total_vulns} vulnérabilité(s) trouvée(s) dans {len(results)} fichier(s)")
    return results


def run_test_generation(results):
    """Étape 2: Générer les tests."""
    print("\n" + "="*60)
    print("🧪 ÉTAPE 2/3 — GÉNÉRATION DES TESTS DE SÉCURITÉ")
    print("="*60)

    results_dict = [r.to_dict() for r in results]
    test_path, all_vulns = generate_from_results(results_dict, "tests/generated")

    print(f"  ✅ {len(all_vulns)} test(s) généré(s) → {test_path}")
    return test_path, all_vulns


def run_tests(test_path: str):
    """Étape 2b: Exécuter les tests générés avec pytest."""
    print("\n  ▶️  Exécution des tests avec pytest...")

    pytest_result = subprocess.run(
        [sys.executable, "-m", "pytest", test_path, "-v", "--tb=short",
         f"--junit-xml=tests/results/junit_report.xml"],
        capture_output=True,
        text=True
    )

    print(pytest_result.stdout[-3000:] if len(pytest_result.stdout) > 3000 else pytest_result.stdout)
    if pytest_result.stderr:
        print("[STDERR]", pytest_result.stderr[-500:])

    return pytest_result.returncode


def run_report(results, all_vulns, scan_target: str):
    """Étape 3: Générer le rapport HTML."""
    print("\n" + "="*60)
    print("📊 ÉTAPE 3/3 — GÉNÉRATION DU RAPPORT HTML")
    print("="*60)

    os.makedirs("reports", exist_ok=True)
    report_path = f"reports/security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    results_dict = [r.to_dict() for r in results]
    generate_html_report(results_dict, all_vulns, report_path, scan_target)

    print(f"  ✅ Rapport généré → {report_path}")
    return report_path


def main():
    parser = argparse.ArgumentParser(
        description="🔒 Security Regression Test Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python runner/run.py sample_app/
  python runner/run.py sample_app/vulnerable_app.py
  python runner/run.py . --fail-on CRITICAL
        """
    )
    parser.add_argument("target", help="Fichier ou dossier à analyser")
    parser.add_argument(
        "--fail-on",
        default="CRITICAL",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
        help="Niveau de sévérité qui bloque le build (défaut: CRITICAL)"
    )
    parser.add_argument("--no-tests", action="store_true", help="Ne pas exécuter pytest")

    args = parser.parse_args()

    print("\n" + "█"*60)
    print("  🔒 SECURITY REGRESSION TEST GENERATOR")
    print(f"  Cible : {args.target}")
    print(f"  Fail-on : {args.fail_on}")
    print(f"  Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("█"*60)

    # 1. Analyse
    results = run_analysis(args.target)

    # 2. Génération + exécution des tests
    test_path, all_vulns = run_test_generation(results)

    os.makedirs("tests/results", exist_ok=True)
    pytest_exit_code = 0
    if not args.no_tests:
        pytest_exit_code = run_tests(test_path)

    # 3. Rapport
    report_path = run_report(results, all_vulns, args.target)

    # 4. Security Gate — Blocage du build
    print("\n" + "="*60)
    print("🚦 SECURITY GATE")
    print("="*60)

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    fail_index = severity_order.index(args.fail_on) if args.fail_on in severity_order else -1

    blocking_vulns = []
    for vuln in all_vulns:
        sev = vuln.get("severity", "INFO")
        if sev in severity_order and severity_order.index(sev) <= fail_index:
            blocking_vulns.append(vuln)

    if blocking_vulns:
        print(f"\n  ❌ BUILD BLOQUÉ — {len(blocking_vulns)} vulnérabilité(s) de niveau >= {args.fail_on} détectée(s):")
        for v in blocking_vulns:
            print(f"     🔴 [{v['severity']}] {v['name']} — {v['file_path']}:{v['line_number']}")
        print(f"\n  📊 Rapport disponible : {report_path}")
        print("="*60 + "\n")
        sys.exit(1)
    else:
        print(f"\n  ✅ BUILD AUTORISÉ — Aucune vulnérabilité bloquante détectée.")
        print(f"\n  📊 Rapport disponible : {report_path}")
        print("="*60 + "\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
