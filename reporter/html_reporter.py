"""
HTML Reporter - Génère un rapport de sécurité visuel et professionnel.
"""

import os
import json
from datetime import datetime
from typing import List, Dict


def generate_html_report(results: list, all_vulns: list, output_path: str, scan_target: str):
    """Génère le rapport HTML complet."""

    total_files = len(results)
    total_vulns = len(all_vulns)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in all_vulns:
        sev = v.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    category_counts = {}
    for v in all_vulns:
        cat = v.get("category", "Other")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    # Score de sécurité (0-100)
    score = max(0, 100 - (counts["CRITICAL"] * 25 + counts["HIGH"] * 10 + counts["MEDIUM"] * 5 + counts["LOW"] * 2))

    scan_date = datetime.now().strftime("%d/%m/%Y à %H:%M:%S")

    vuln_rows = ""
    for v in all_vulns:
        sev = v.get("severity", "INFO")
        sev_class = {"CRITICAL": "badge-critical", "HIGH": "badge-high",
                     "MEDIUM": "badge-medium", "LOW": "badge-low", "INFO": "badge-info"}.get(sev, "badge-info")
        line_content = v.get("line_content", "").strip().replace("<", "&lt;").replace(">", "&gt;")
        vuln_rows += f"""
        <tr>
            <td><span class="badge {sev_class}">{sev}</span></td>
            <td><strong>{v.get('name','')}</strong></td>
            <td>{v.get('category','')}</td>
            <td><code>{os.path.basename(v.get('file_path',''))}</code></td>
            <td>Ligne {v.get('line_number','')}</td>
            <td><span class="cwe-tag">{v.get('cwe','')}</span></td>
            <td class="code-snippet">{line_content[:80]}{'...' if len(line_content) > 80 else ''}</td>
            <td class="recommendation">{v.get('recommendation','')}</td>
        </tr>"""

    file_rows = ""
    for r in results:
        vcount = len(r.get("vulnerabilities", []))
        file_rows += f"""
        <tr>
            <td><code>{r.get('file_path','')}</code></td>
            <td>{r.get('language','').capitalize()}</td>
            <td>{r.get('total_lines',0)}</td>
            <td><strong {'style="color:var(--critical)"' if vcount > 0 else ''}>{vcount}</strong></td>
            <td>{r.get('scan_duration', 0)}s</td>
        </tr>"""

    cat_badges = ""
    for cat, cnt in sorted(category_counts.items(), key=lambda x: -x[1]):
        cat_badges += f'<div class="cat-badge"><span>{cat}</span><strong>{cnt}</strong></div>'

    score_color = "#22c55e" if score >= 80 else "#f59e0b" if score >= 50 else "#ef4444"
    score_label = "Bon" if score >= 80 else "Moyen" if score >= 50 else "Critique"

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Report — {scan_target}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;600;800&display=swap');

  :root {{
    --bg: #0a0e1a;
    --surface: #111827;
    --surface2: #1a2236;
    --border: #1e2d45;
    --text: #e2e8f0;
    --muted: #64748b;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #eab308;
    --low: #22c55e;
    --info: #3b82f6;
    --accent: #6366f1;
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Syne', sans-serif;
    min-height: 100vh;
  }}

  /* ── HEADER ── */
  .header {{
    background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
    border-bottom: 1px solid var(--border);
    padding: 40px 60px;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute;
    top: -50%;
    left: -10%;
    width: 500px;
    height: 500px;
    background: radial-gradient(circle, rgba(99,102,241,0.12) 0%, transparent 70%);
    pointer-events: none;
  }}
  .header-top {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 20px;
  }}
  .logo {{
    display: flex;
    align-items: center;
    gap: 14px;
  }}
  .logo-icon {{
    width: 48px;
    height: 48px;
    background: linear-gradient(135deg, var(--accent), #818cf8);
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 22px;
  }}
  .logo-text h1 {{
    font-size: 1.4rem;
    font-weight: 800;
    letter-spacing: -0.5px;
  }}
  .logo-text p {{
    font-size: 0.75rem;
    color: var(--muted);
    font-family: 'JetBrains Mono', monospace;
  }}
  .header-meta {{
    text-align: right;
    font-size: 0.8rem;
    color: var(--muted);
    font-family: 'JetBrains Mono', monospace;
  }}
  .header-meta strong {{
    color: var(--text);
    display: block;
    font-size: 0.9rem;
  }}

  /* ── MAIN ── */
  .main {{
    max-width: 1400px;
    margin: 0 auto;
    padding: 40px 60px;
  }}

  /* ── SCORE BANNER ── */
  .score-banner {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 30px 40px;
    display: flex;
    align-items: center;
    gap: 40px;
    margin-bottom: 32px;
    flex-wrap: wrap;
  }}
  .score-circle {{
    width: 100px;
    height: 100px;
    border-radius: 50%;
    border: 4px solid {score_color};
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    box-shadow: 0 0 30px {score_color}44;
  }}
  .score-circle .score-num {{
    font-size: 2rem;
    font-weight: 800;
    color: {score_color};
    line-height: 1;
  }}
  .score-circle .score-sub {{
    font-size: 0.65rem;
    color: var(--muted);
  }}
  .score-info h2 {{ font-size: 1.3rem; font-weight: 800; margin-bottom: 6px; }}
  .score-info p {{ color: var(--muted); font-size: 0.9rem; max-width: 500px; }}
  .score-label {{
    margin-left: auto;
    font-size: 1.1rem;
    font-weight: 700;
    color: {score_color};
    background: {score_color}22;
    padding: 8px 20px;
    border-radius: 50px;
    border: 1px solid {score_color}44;
  }}

  /* ── KPI CARDS ── */
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }}
  .kpi-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    text-align: center;
    transition: transform 0.2s;
  }}
  .kpi-card:hover {{ transform: translateY(-2px); }}
  .kpi-card .kpi-num {{
    font-size: 2.2rem;
    font-weight: 800;
    line-height: 1;
    margin-bottom: 4px;
  }}
  .kpi-card .kpi-label {{
    font-size: 0.75rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 1px;
  }}
  .kpi-critical .kpi-num {{ color: var(--critical); }}
  .kpi-high .kpi-num {{ color: var(--high); }}
  .kpi-medium .kpi-num {{ color: var(--medium); }}
  .kpi-low .kpi-num {{ color: var(--low); }}
  .kpi-total .kpi-num {{ color: var(--accent); }}

  /* ── SECTIONS ── */
  .section {{ margin-bottom: 32px; }}
  .section-title {{
    font-size: 1rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: var(--muted);
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 10px;
  }}
  .section-title::after {{
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }}

  /* ── CATEGORIES ── */
  .categories {{
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 32px;
  }}
  .cat-badge {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 16px;
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 0.85rem;
  }}
  .cat-badge strong {{
    background: var(--accent);
    color: white;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.75rem;
  }}

  /* ── TABLE ── */
  .table-wrap {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: auto;
    margin-bottom: 32px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.82rem;
  }}
  thead {{
    background: var(--surface2);
    border-bottom: 1px solid var(--border);
  }}
  thead th {{
    padding: 12px 16px;
    text-align: left;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--muted);
    font-weight: 600;
  }}
  tbody tr {{
    border-bottom: 1px solid var(--border);
    transition: background 0.15s;
  }}
  tbody tr:last-child {{ border-bottom: none; }}
  tbody tr:hover {{ background: var(--surface2); }}
  tbody td {{
    padding: 12px 16px;
    vertical-align: top;
  }}
  .badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 50px;
    font-size: 0.7rem;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.5px;
  }}
  .badge-critical {{ background: #ef444422; color: var(--critical); border: 1px solid #ef444444; }}
  .badge-high {{ background: #f9731622; color: var(--high); border: 1px solid #f9731644; }}
  .badge-medium {{ background: #eab30822; color: var(--medium); border: 1px solid #eab30844; }}
  .badge-low {{ background: #22c55e22; color: var(--low); border: 1px solid #22c55e44; }}
  .badge-info {{ background: #3b82f622; color: var(--info); border: 1px solid #3b82f644; }}

  code {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    background: var(--surface2);
    padding: 2px 6px;
    border-radius: 4px;
    color: #a5b4fc;
  }}
  .code-snippet {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: var(--muted);
    max-width: 200px;
    word-break: break-all;
  }}
  .cwe-tag {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: #818cf8;
    background: #6366f122;
    padding: 2px 8px;
    border-radius: 4px;
  }}
  .recommendation {{
    font-size: 0.78rem;
    color: var(--muted);
    max-width: 250px;
  }}

  /* ── FOOTER ── */
  .footer {{
    text-align: center;
    padding: 30px;
    color: var(--muted);
    font-size: 0.8rem;
    border-top: 1px solid var(--border);
    font-family: 'JetBrains Mono', monospace;
  }}

  /* ── EMPTY STATE ── */
  .empty-state {{
    text-align: center;
    padding: 60px;
    color: var(--muted);
  }}
  .empty-state .icon {{ font-size: 3rem; margin-bottom: 16px; }}
  .empty-state h3 {{ color: var(--low); font-size: 1.3rem; margin-bottom: 8px; }}

  @media (max-width: 768px) {{
    .header, .main {{ padding: 20px; }}
    .score-banner {{ flex-direction: column; text-align: center; }}
    .score-label {{ margin: 0 auto; }}
  }}
</style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <div class="logo">
      <div class="logo-icon">🔒</div>
      <div class="logo-text">
        <h1>Security Regression Report</h1>
        <p>Security Regression Test Generator — DevSecOps Pipeline</p>
      </div>
    </div>
    <div class="header-meta">
      <strong>{scan_target}</strong>
      Scan du {scan_date}<br>
      {total_files} fichier(s) analysé(s)
    </div>
  </div>
</div>

<div class="main">

  <!-- Score -->
  <div class="score-banner">
    <div class="score-circle">
      <span class="score-num">{score}</span>
      <span class="score-sub">/100</span>
    </div>
    <div class="score-info">
      <h2>Score de Sécurité</h2>
      <p>
        {'Aucune vulnérabilité critique détectée. Le code respecte les bonnes pratiques de sécurité.' if score >= 80 else
         f'Des vulnérabilités ont été détectées. Corrigez en priorité les {counts["CRITICAL"]} faille(s) critique(s) et {counts["HIGH"]} haute(s).' }
      </p>
    </div>
    <div class="score-label">{score_label}</div>
  </div>

  <!-- KPIs -->
  <div class="kpi-grid">
    <div class="kpi-card kpi-total">
      <div class="kpi-num">{total_vulns}</div>
      <div class="kpi-label">Total Vulnérabilités</div>
    </div>
    <div class="kpi-card kpi-critical">
      <div class="kpi-num">{counts['CRITICAL']}</div>
      <div class="kpi-label">🔴 Critical</div>
    </div>
    <div class="kpi-card kpi-high">
      <div class="kpi-num">{counts['HIGH']}</div>
      <div class="kpi-label">🟠 High</div>
    </div>
    <div class="kpi-card kpi-medium">
      <div class="kpi-num">{counts['MEDIUM']}</div>
      <div class="kpi-label">🟡 Medium</div>
    </div>
    <div class="kpi-card kpi-low">
      <div class="kpi-num">{counts['LOW']}</div>
      <div class="kpi-label">🟢 Low</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-num" style="color:var(--muted)">{total_files}</div>
      <div class="kpi-label">Fichiers Scannés</div>
    </div>
  </div>

  <!-- Catégories -->
  <div class="section">
    <div class="section-title">📂 Catégories détectées</div>
    <div class="categories">
      {cat_badges if cat_badges else '<p style="color:var(--muted)">Aucune catégorie</p>'}
    </div>
  </div>

  <!-- Tableau des vulnérabilités -->
  <div class="section">
    <div class="section-title">🔍 Détail des vulnérabilités</div>
    {'<div class="table-wrap"><table><thead><tr><th>Sévérité</th><th>Nom</th><th>Catégorie</th><th>Fichier</th><th>Position</th><th>CWE</th><th>Code</th><th>Recommandation</th></tr></thead><tbody>' + vuln_rows + '</tbody></table></div>' if vuln_rows else '<div class="empty-state"><div class="icon">✅</div><h3>Aucune vulnérabilité détectée</h3><p>Le code analysé est propre.</p></div>'}
  </div>

  <!-- Fichiers analysés -->
  <div class="section">
    <div class="section-title">📄 Fichiers analysés</div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Chemin</th>
            <th>Langage</th>
            <th>Lignes</th>
            <th>Vulnérabilités</th>
            <th>Durée scan</th>
          </tr>
        </thead>
        <tbody>
          {file_rows}
        </tbody>
      </table>
    </div>
  </div>

</div>

<div class="footer">
  Security Regression Test Generator — Généré le {scan_date} — DevSecOps Pipeline
</div>

</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path
