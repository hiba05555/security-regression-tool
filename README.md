# 🔒 Security Regression Test Generator

> **Projet 13 — DevSecOps**  
> Génération automatique de tests de sécurité intégrés dans un pipeline CI/CD GitHub Actions.

---

## 📌 Description

Ce projet implémente un **Security Regression Test Generator** complet qui :

1. **Analyse** automatiquement du code Python et JavaScript pour détecter des vulnérabilités
2. **Génère** des tests de sécurité (pytest) basés sur les failles détectées
3. **Exécute** les tests et produit un rapport HTML visuel
4. **Bloque le build** dans GitHub Actions si des vulnérabilités critiques sont trouvées

---

## 🏗️ Architecture

```
security-regression-tool/
│
├── analyzer/
│   └── security_analyzer.py    # Détecte les vulnérabilités (Python + JS)
│
├── generator/
│   └── test_generator.py       # Génère les tests pytest automatiquement
│
├── runner/
│   └── run.py                  # Orchestre tout le pipeline
│
├── reporter/
│   └── html_reporter.py        # Génère le rapport HTML visuel
│
├── sample_app/
│   ├── vulnerable_app.py       # App Python avec vulnérabilités (démo)
│   └── vulnerable_app.js       # App JavaScript avec vulnérabilités (démo)
│
├── .github/
│   └── workflows/
│       └── security-tests.yml  # Pipeline GitHub Actions (CI/CD)
│
├── requirements.txt
└── README.md
```

---

## 🔍 Vulnérabilités détectées

| ID | Vulnérabilité | Langages | CWE |
|----|--------------|----------|-----|
| PY001 / JS001 | SQL Injection | Python, JS | CWE-89 |
| PY002 / JS002 | Hardcoded Secret/Credential | Python, JS | CWE-798 |
| PY003 / JS004 | Command Injection | Python, JS | CWE-78 |
| PY004 | Weak Hashing (MD5/SHA1) | Python | CWE-328 |
| PY005 / JS007 | Path Traversal | Python, JS | CWE-22 |
| PY006 | Insecure Deserialization (pickle) | Python | CWE-502 |
| PY007 / JS006 | Insecure Random Number | Python, JS | CWE-338 |
| PY008 / JS003 | XSS — Unescaped Output | Python, JS | CWE-79 |
| JS005 | Dangerous eval() | JavaScript | CWE-95 |
| JS008 | Prototype Pollution | JavaScript | CWE-1321 |

---

## 🚀 Installation & Utilisation

### Prérequis

```bash
python 3.9+
git
```

### Installation

```bash
git clone https://github.com/<votre-username>/security-regression-tool.git
cd security-regression-tool
pip install -r requirements.txt
```

### Lancer le scan

```bash
# Scanner le dossier sample_app (démo)
python runner/run.py sample_app/

# Scanner un fichier spécifique
python runner/run.py sample_app/vulnerable_app.py

# Scanner avec un seuil de blocage différent
python runner/run.py sample_app/ --fail-on HIGH

# Scanner sans exécuter pytest
python runner/run.py sample_app/ --no-tests
```

### Options disponibles

| Option | Description | Défaut |
|--------|-------------|--------|
| `target` | Fichier ou dossier à analyser | requis |
| `--fail-on` | Niveau bloquant (CRITICAL/HIGH/MEDIUM/LOW/NONE) | CRITICAL |
| `--no-tests` | Ne pas exécuter pytest | désactivé |

---

## 📊 Exemple de sortie

```
████████████████████████████████████████████████████████████
  🔒 SECURITY REGRESSION TEST GENERATOR
  Cible : sample_app/
  Fail-on : CRITICAL
  Date : 2024-01-15 14:32:10
████████████████████████████████████████████████████████████

============================================================
🔍 ÉTAPE 1/3 — ANALYSE DES VULNÉRABILITÉS
============================================================
  📄 sample_app/vulnerable_app.py → 8 vulnérabilité(s) (python)
     🔴 [CRITICAL] SQL Injection — Ligne 22 (CWE-89)
     🟠 [HIGH] Hardcoded Secret / Credential — Ligne 8 (CWE-798)
     🔴 [CRITICAL] Command Injection — Ligne 28 (CWE-78)
     ...

============================================================
🧪 ÉTAPE 2/3 — GÉNÉRATION DES TESTS DE SÉCURITÉ
============================================================
  ✅ 16 test(s) généré(s) → tests/generated/test_security_generated.py

============================================================
📊 ÉTAPE 3/3 — GÉNÉRATION DU RAPPORT HTML
============================================================
  ✅ Rapport généré → reports/security_report_20240115_143215.html

============================================================
🚦 SECURITY GATE
============================================================
  ❌ BUILD BLOQUÉ — 3 vulnérabilité(s) de niveau >= CRITICAL détectée(s)
```

---

## ⚙️ Pipeline GitHub Actions

Le pipeline se déclenche automatiquement à chaque :
- **Push** sur `main`, `develop`, ou `feature/**`
- **Pull Request** vers `main` ou `develop`

### Étapes du pipeline

```yaml
1. 📥 Checkout du code
2. 🐍 Setup Python 3.11
3. 📦 Installation des dépendances
4. 🔍 Analyse de sécurité
5. 📊 Upload du rapport HTML (artifact)
6. 🚦 Security Gate — bloque le build si vulnérabilité >= seuil
```

### Résultats disponibles dans GitHub Actions

- **Artifacts** : rapport HTML téléchargeable depuis l'onglet Actions
- **Exit code** : 0 = build OK, 1 = build bloqué

---

## 🔗 Concepts DevSecOps

| Concept | Implémentation |
|---------|---------------|
| **Shift Left Security** | Scan dès le push, avant le déploiement |
| **Security as Code** | Règles de détection versionnées avec le code |
| **Automated Testing** | Tests générés sans intervention humaine |
| **Security Gate** | Blocage automatique du pipeline CI/CD |
| **Regression Testing** | Chaque commit est re-scanné pour éviter les régressions |

---

## 📈 Score de sécurité

Le rapport calcule un score de 0 à 100 :

| Score | Statut | Calcul |
|-------|--------|--------|
| 80-100 | ✅ Bon | Peu ou pas de vulnérabilités |
| 50-79 | ⚠️ Moyen | Vulnérabilités Medium/High |
| 0-49 | ❌ Critique | Vulnérabilités Critical/High nombreuses |

**Formule** : `score = max(0, 100 - (CRITICAL×25 + HIGH×10 + MEDIUM×5 + LOW×2))`

---

## 👥 Auteurs

Projet réalisé dans le cadre du cours **DevSecOps**.

---

## 📄 Licence

MIT License — Libre d'utilisation à des fins académiques.
