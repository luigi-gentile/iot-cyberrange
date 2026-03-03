#!/usr/bin/env python3
"""
generate_figures.py - IoT Cyberrange comparative analysis figures

Usage:
    python3 metrics/generate_figures.py

Output: metrics/figures/fig{1..5}_*.png
"""

import json
import glob
import os
import sys
import warnings
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
from matplotlib.patches import FancyBboxPatch

warnings.filterwarnings('ignore', category=UserWarning)

# ── paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(SCRIPT_DIR, 'results')
FIGURES_DIR = os.path.join(SCRIPT_DIR, 'figures')
os.makedirs(FIGURES_DIR, exist_ok=True)

# ── design tokens ─────────────────────────────────────────────────────────────
PALETTE = {
    'BREACHED':    '#C62828',
    'COMPROMISED': '#E64A19',
    'DEGRADED':    '#F57F17',
    'DETECTED':    '#0277BD',
    'BLOCKED':     '#2E7D32',
}
PALETTE_LIGHT = {k: v + '22' for k, v in PALETTE.items()}   # transparent fill

C_INSECURE = '#E53935'
C_SECURE   = '#1E88E5'
C_BASE     = '#78909C'
C_ATTACK   = '#E53935'
C_GRID     = '#F0F0F0'
C_TEXT     = '#212121'
C_SUBTEXT  = '#757575'

plt.rcParams.update({
    'font.family':         'DejaVu Sans',
    'font.size':           11,
    'text.color':          C_TEXT,
    'axes.labelcolor':     C_TEXT,
    'xtick.color':         C_SUBTEXT,
    'ytick.color':         C_SUBTEXT,
    'axes.edgecolor':      '#E0E0E0',
    'axes.titlesize':      14,
    'axes.titleweight':    'bold',
    'axes.titlepad':       14,
    'axes.spines.top':     False,
    'axes.spines.right':   False,
    'axes.grid':           True,
    'axes.grid.axis':      'y',
    'grid.color':          C_GRID,
    'grid.linewidth':      1,
    'figure.dpi':          150,
    'savefig.dpi':         220,
    'savefig.bbox':        'tight',
    'savefig.facecolor':   'white',
    'figure.facecolor':    'white',
})

# ── data loading ──────────────────────────────────────────────────────────────
def load_latest(env: str) -> dict:
    files = sorted(glob.glob(os.path.join(RESULTS_DIR, f'campaign_{env}_*.json')))
    if not files:
        print(f'ERROR: no results found for "{env}" in {RESULTS_DIR}', file=sys.stderr)
        sys.exit(1)
    path = files[-1]
    print(f'  [{env}] {os.path.basename(path)}')
    return json.load(open(path))

print('Loading campaign data...')
insecure = load_latest('insecure')
secure   = load_latest('secure')

SCENARIOS = [
    ('scenario_1', 'S1', 'Eavesdropping'),
    ('scenario_2', 'S2', 'Message\nInjection'),
    ('scenario_3', 'S3', 'Denial\nof Service'),
    ('scenario_4', 'S4', 'Brute\nForce'),
    ('scenario_5', 'S5', 'Lateral\nMovement'),
]

# ── outcome classification ────────────────────────────────────────────────────
def insecure_outcome(snum, sdata):
    if snum == 1: return 'BREACHED'
    if snum == 2:
        total = sum(v.get('anomalies', 0)
                    for v in sdata['during_attack']['integrity'].values())
        return 'COMPROMISED' if total > 0 else 'DEGRADED'
    if snum == 3: return 'DEGRADED'
    if snum == 4: return 'COMPROMISED'
    if snum == 5: return 'COMPROMISED'

def secure_outcome(snum, sdata):
    detected = sdata.get('ttd', {}).get('detected', False)
    if snum == 1: return 'BLOCKED'
    if snum == 2: return 'BLOCKED'
    if snum == 3: return 'DETECTED' if detected else 'DEGRADED'
    if snum == 4: return 'DETECTED' if detected else 'BLOCKED'
    if snum == 5: return 'DETECTED' if detected else 'BLOCKED'

outcomes = []
for key, sid, name in SCENARIOS:
    snum = int(key.split('_')[1])
    outcomes.append({
        'key':     key,
        'sid':     sid,
        'name':    name,
        'insecure': insecure_outcome(snum, insecure['scenarios'][key]),
        'secure':   secure_outcome(snum,   secure['scenarios'][key]),
        'ttd':      secure['scenarios'][key].get('ttd', {}),
        'isec_data': insecure['scenarios'][key],
        'sec_data':  secure['scenarios'][key],
    })

# ═══════════════════════════════════════════════════════════════════════════════
# FIG 1 — Scenario Security Outcomes
# ═══════════════════════════════════════════════════════════════════════════════
print('\n[1/5] Scenario Outcomes...')

fig, ax = plt.subplots(figsize=(13, 5))
ax.set_xlim(-0.5, len(SCENARIOS) - 0.5)
ax.set_ylim(-0.2, 2.4)
ax.axis('off')
fig.patch.set_facecolor('white')

OUTCOME_LABEL = {
    'BREACHED':    '🔴  BREACHED',
    'COMPROMISED': '🟠  COMPROMISED',
    'DEGRADED':    '🟡  DEGRADED',
    'DETECTED':    '🔵  DETECTED',
    'BLOCKED':     '🟢  BLOCKED',
}

# column headers
ax.text(-0.5, 2.28, 'INSECURE', fontsize=11, fontweight='bold',
        color=C_INSECURE, va='center')
ax.text(-0.5, 1.13, 'SECURE', fontsize=11, fontweight='bold',
        color=C_SECURE, va='center')

for col, row in enumerate(outcomes):
    x = col

    # scenario label at top
    ax.text(x, 2.75, row['sid'], ha='center', va='center',
            fontsize=13, fontweight='bold', color=C_TEXT)
    ax.text(x, 2.55, row['name'].replace('\n', ' '),
            ha='center', va='center', fontsize=9, color=C_SUBTEXT)

    for row_idx, (env_key, yc) in enumerate([('insecure', 1.85), ('secure', 0.7)]):
        outcome = row[env_key]
        color   = PALETTE[outcome]

        # background rounded box
        box = FancyBboxPatch((x - 0.42, yc - 0.52), 0.84, 0.84,
                             boxstyle='round,pad=0.04',
                             facecolor=color, edgecolor='white',
                             linewidth=2, zorder=2)
        ax.add_patch(box)

        # outcome text
        label = outcome
        ax.text(x, yc + 0.1, label,
                ha='center', va='center', fontsize=9.5,
                fontweight='bold', color='white', zorder=3)

        # TTD annotation for secure detected
        if env_key == 'secure' and outcome == 'DETECTED':
            ttd_s = row['ttd'].get('ttd_seconds')
            if ttd_s:
                ax.text(x, yc - 0.2, f'TTD {ttd_s:.1f}s',
                        ha='center', va='center', fontsize=8,
                        color='white', zorder=3,
                        fontweight='bold')

# legend
legend_items = [
    mpatches.Patch(color=PALETTE[o], label=o)
    for o in ['BREACHED', 'COMPROMISED', 'DEGRADED', 'DETECTED', 'BLOCKED']
]
ax.legend(handles=legend_items, loc='lower right', fontsize=9,
          framealpha=0.95, edgecolor='#e0e0e0',
          bbox_to_anchor=(1.0, -0.05), ncol=5,
          handlelength=1.2, handleheight=1.0)

ax.set_title('Security Outcome per Attack Scenario — Insecure vs Secure',
             fontsize=14, fontweight='bold', pad=6, y=1.0)

out = os.path.join(FIGURES_DIR, 'fig1_scenario_outcomes.png')
plt.savefig(out)
plt.close()
print(f'  → {out}')

# ═══════════════════════════════════════════════════════════════════════════════
# FIG 2 — MQTT Latency
# ═══════════════════════════════════════════════════════════════════════════════
print('[2/5] MQTT Latency...')

fig, axes = plt.subplots(1, 2, figsize=(13, 5), sharey=True,
                         layout='constrained')

x_labels = [f"{row['sid']}\n{row['name']}" for row in outcomes]
x = np.arange(len(outcomes))
w = 0.36

for ax, (env_data, env_name, bar_col) in zip(axes, [
    (insecure, 'Insecure Environment', C_INSECURE),
    (secure,   'Secure Environment',   C_SECURE),
]):
    base_vals   = [env_data['scenarios'][r['key']]['baseline']['latency']['avg_ms']
                   for r in outcomes]
    attack_vals = [env_data['scenarios'][r['key']]['during_attack']['latency']['avg_ms']
                   for r in outcomes]

    b1 = ax.bar(x - w/2, base_vals,   w, label='Baseline',
                color=C_BASE, alpha=0.85, edgecolor='white', linewidth=1.5)
    b2 = ax.bar(x + w/2, attack_vals, w, label='Under Attack',
                color=bar_col, alpha=0.9, edgecolor='white', linewidth=1.5)

    ax.set_xticks(x)
    ax.set_xticklabels(x_labels, fontsize=9)
    ax.set_ylabel('avg latency (ms)', fontsize=10)
    ax.set_title(env_name, fontsize=13, fontweight='bold')
    ax.legend(fontsize=9, framealpha=0.9, edgecolor='#e0e0e0')
    ax.yaxis.grid(True, color=C_GRID, linewidth=1)
    ax.set_axisbelow(True)

    all_vals = base_vals + attack_vals
    ax.set_ylim(0, max(all_vals) * 1.40)

    for rect, val in zip([*b1, *b2], base_vals + attack_vals):
        ax.text(rect.get_x() + rect.get_width()/2,
                rect.get_height() + 0.015,
                f'{val:.2f}', ha='center', va='bottom',
                fontsize=7.5, color=C_TEXT)

fig.suptitle('MQTT Round-Trip Latency — Baseline vs Under Attack',
             fontsize=14, fontweight='bold')
out = os.path.join(FIGURES_DIR, 'fig2_latency.png')
plt.savefig(out)
plt.close()
print(f'  → {out}')

# ═══════════════════════════════════════════════════════════════════════════════
# FIG 3 — TTD Suricata
# ═══════════════════════════════════════════════════════════════════════════════
print('[3/5] Time-To-Detect...')

ttd_data = [(r['name'].replace('\n',' '), r['ttd']) for r in outcomes]
detected = [(name, t) for name, t in ttd_data if t.get('detected')]
not_det  = [(name, t) for name, t in ttd_data if not t.get('detected')]

fig, ax = plt.subplots(figsize=(11, 4.8))

ys     = np.arange(len(ttd_data))
colors = [PALETTE['DETECTED'] if t.get('detected') else '#CFD8DC'
          for _, t in ttd_data]
vals   = [t.get('ttd_seconds') or 0 for _, t in ttd_data]
labels = [name for name, _ in ttd_data]

bars = ax.barh(ys, vals, color=colors, edgecolor='white',
               linewidth=1.5, height=0.55)

for i, (bar, (name, ttd_info)) in enumerate(zip(bars, ttd_data)):
    if ttd_info.get('detected'):
        n_alerts = ttd_info.get('alert_count', 0)
        ax.text(bar.get_width() + 0.2,
                bar.get_y() + bar.get_height()/2,
                f"{ttd_info['ttd_seconds']:.1f} s  ·  {n_alerts} alert{'s' if n_alerts!=1 else ''}",
                va='center', fontsize=10, fontweight='bold',
                color=PALETTE['DETECTED'])
    else:
        ax.text(0.25, bar.get_y() + bar.get_height()/2,
                'blocked by design — not applicable',
                va='center', fontsize=9, style='italic', color='#90A4AE')

ax.set_yticks(ys)
ax.set_yticklabels(labels, fontsize=10)
ax.set_xlabel('Time-To-Detect (seconds)', fontsize=10)
ax.set_xlim(0, max(vals) * 2.2 if any(vals) else 20)
ax.set_title('Suricata IDS — Time-To-Detect per Attack Scenario (Secure Environment)',
             fontsize=13, fontweight='bold')
ax.yaxis.grid(False)
ax.xaxis.grid(True, color=C_GRID, linewidth=1)
ax.set_axisbelow(True)
ax.spines['left'].set_visible(False)

det_patch = mpatches.Patch(color=PALETTE['DETECTED'],  label='Detected by Suricata')
na_patch  = mpatches.Patch(color='#CFD8DC', label='Not applicable (prevented by controls)')
ax.legend(handles=[det_patch, na_patch], fontsize=9, loc='lower right',
          framealpha=0.95, edgecolor='#e0e0e0')

plt.tight_layout()
out = os.path.join(FIGURES_DIR, 'fig3_ttd.png')
plt.savefig(out)
plt.close()
print(f'  → {out}')

# ═══════════════════════════════════════════════════════════════════════════════
# FIG 4 — Data Integrity (Scenario 2 injection)
# ═══════════════════════════════════════════════════════════════════════════════
print('[4/5] Data Integrity...')

measurements = ['Temperature', 'Humidity', 'Power']

def get_anomalies(campaign, key, phase):
    integ = campaign['scenarios'][key][phase]['integrity']
    return [integ.get(m.lower(), {}).get('anomalies', 0) for m in measurements]

ins_base   = get_anomalies(insecure, 'scenario_2', 'baseline')
ins_attack = get_anomalies(insecure, 'scenario_2', 'during_attack')
sec_base   = get_anomalies(secure,   'scenario_2', 'baseline')
sec_attack = get_anomalies(secure,   'scenario_2', 'during_attack')

fig, axes = plt.subplots(1, 2, figsize=(12, 5), sharey=True,
                         layout='constrained')

x = np.arange(len(measurements))
w = 0.36

for ax, (base_v, attack_v, env_name, bar_col) in zip(axes, [
    (ins_base, ins_attack, 'Insecure — S2 Message Injection', C_INSECURE),
    (sec_base, sec_attack, 'Secure — S2 Message Injection',   C_SECURE),
]):
    b1 = ax.bar(x - w/2, base_v,   w, label='Baseline',
                color='#80CBC4', edgecolor='white', linewidth=1.5)
    b2 = ax.bar(x + w/2, attack_v, w, label='Under Attack',
                color=bar_col, alpha=0.9, edgecolor='white', linewidth=1.5)

    ax.set_xticks(x)
    ax.set_xticklabels(measurements, fontsize=10)
    ax.set_ylabel('Anomalous readings detected', fontsize=10)
    ax.set_title(env_name, fontsize=12, fontweight='bold')
    ax.legend(fontsize=9, framealpha=0.9, edgecolor='#e0e0e0')
    ax.yaxis.grid(True, color=C_GRID)
    ax.set_axisbelow(True)

    for rect, val in zip([*b1, *b2], base_v + attack_v):
        if val > 0:
            ax.text(rect.get_x() + rect.get_width()/2,
                    rect.get_height() + 0.05,
                    str(int(val)), ha='center', va='bottom',
                    fontsize=11, fontweight='bold', color=C_TEXT)
        else:
            ax.text(rect.get_x() + rect.get_width()/2,
                    0.15, '0', ha='center', va='bottom',
                    fontsize=10, color='#9E9E9E')

    max_v = max(max(base_v), max(attack_v), 1)
    ax.set_ylim(0, max_v * 1.5)

fig.suptitle('Data Integrity — Anomalous Readings During Injection Attack (S2)',
             fontsize=14, fontweight='bold')
out = os.path.join(FIGURES_DIR, 'fig4_integrity.png')
plt.savefig(out)
plt.close()
print(f'  → {out}')

# ═══════════════════════════════════════════════════════════════════════════════
# FIG 5 — Executive Summary Table
# ═══════════════════════════════════════════════════════════════════════════════
print('[5/5] Executive Summary...')

rows_data = []
for row in outcomes:
    snum  = int(row['key'].split('_')[1])
    ttd_s = row['ttd'].get('ttd_seconds')
    ttd_str = f"{ttd_s:.1f} s" if ttd_s else '—'
    lat_ins = row['isec_data']['during_attack']['latency']['avg_ms']
    lat_sec = row['sec_data']['during_attack']['latency']['avg_ms']
    rows_data.append([
        f"{row['sid']}  {row['name'].replace(chr(10), ' ')}",
        row['insecure'],
        row['secure'],
        ttd_str,
        f"{lat_ins:.2f} ms",
        f"{lat_sec:.2f} ms",
    ])

col_labels = [
    'Scenario',
    'Insecure\nOutcome',
    'Secure\nOutcome',
    'TTD\n(Suricata)',
    'Latency\nInsecure',
    'Latency\nSecure',
]
col_widths = [0.22, 0.14, 0.14, 0.12, 0.13, 0.13]

fig, ax = plt.subplots(figsize=(14, 3.8))
ax.axis('off')

tbl = ax.table(
    cellText=rows_data,
    colLabels=col_labels,
    loc='center',
    cellLoc='center',
)
tbl.auto_set_font_size(False)
tbl.set_fontsize(10)

n_rows = len(rows_data) + 1
n_cols = len(col_labels)

for (r, c), cell in tbl.get_celld().items():
    cell.set_edgecolor('#E0E0E0')
    cell.set_linewidth(0.8)

    if r == 0:
        cell.set_facecolor('#1565C0')
        cell.set_text_props(color='white', fontweight='bold', fontsize=9.5)
        cell.set_height(0.22)
    elif c in (1, 2):
        val = rows_data[r - 1][c]
        if val in PALETTE:
            cell.set_facecolor(PALETTE[val])
            cell.set_text_props(color='white', fontweight='bold')
        else:
            cell.set_facecolor('#FAFAFA' if r % 2 else 'white')
    else:
        cell.set_facecolor('#FAFAFA' if r % 2 else 'white')
        cell.set_text_props(color=C_TEXT)

    if r > 0:
        cell.set_height(0.16)

    for j, cw in enumerate(col_widths):
        tbl[(r, j)].set_width(cw)

ax.set_title('Executive Summary — IoT Cyberrange Security Comparison',
             fontsize=14, fontweight='bold', pad=16)

plt.tight_layout()
out = os.path.join(FIGURES_DIR, 'fig5_summary_table.png')
plt.savefig(out)
plt.close()
print(f'  → {out}')

# ─────────────────────────────────────────────────────────────────────────────
print(f'\nAll figures saved to: {FIGURES_DIR}')
