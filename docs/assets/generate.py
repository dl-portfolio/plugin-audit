#!/usr/bin/env python3
"""Generate the README graphics (stdlib only): banner and pipeline in light and dark variants, plus badges.

    python3 docs/assets/generate.py      # writes docs/assets/*.svg

Edit the data below (stages, chips, badges) and re-run; the README embeds the files with <picture> so GitHub picks
the variant that matches the reader's theme.
"""
import os
from xml.sax.saxutils import escape

OUT = os.path.dirname(os.path.abspath(__file__))
FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"

THEMES = {
    'dark': dict(bg0='#0b1220', bg1='#14213d', grid='#ffffff', grid_op=0.04, title='#f8fafc', text='#cbd5e1',
                 muted='#94a3b8', accent='#38bdf8', accent_text='#7dd3fc', good='#4ade80', host='#a78bfa',
                 host_text='#c4b5fd', card='#ffffff', card_op=0.04, card_stroke_op=0.12, number_text='#0b1220',
                 shield_fill_op=0.28, magnifier='#f8fafc'),
    'light': dict(bg0='#f8fafc', bg1='#e0f2fe', grid='#0f172a', grid_op=0.05, title='#0f172a', text='#1e293b',
                  muted='#475569', accent='#0284c7', accent_text='#0369a1', good='#16a34a', host='#7c3aed',
                  host_text='#6d28d9', card='#ffffff', card_op=0.85, card_stroke_op=0.18, number_text='#ffffff',
                  shield_fill_op=0.18, magnifier='#0f172a'),
}

CHIPS = ['Throwaway VM', 'Decoy credentials', 'Network sinkhole', 'macOS impersonation', 'Contained LLM review']

# (title, where, line 1, line 2, icon)
STAGES = [
    ('Fetch', 'VM', 'Downloads the target at a pinned commit, inside the VM.',
     'Git never parses it on the host; symlinks are stripped on export.', 'fetch'),
    ('Static scan', 'VM', 'Own rules plus gitleaks, osv-scanner, semgrep, SkillSpector, Cisco.',
     'Runs as a user with no network; never executes target code.', 'static'),
    ('Scenario', 'VM + HOST', 'Writes install.sh and run.sh: how a user would install and use it.',
     'Generic baseline plus a contained LLM that reads the README as data.', 'scenario'),
    ('Runtime test', 'VM', 'Runs the scenario: install, run, and run-darwin (told it is a Mac).',
     'Decoy credentials, network sinkhole, strace, persistence diff.', 'runtime'),
    ('Review', 'HOST', 'A read-only LLM checks code against both summaries.',
     'Writes the report: verdict, top risks, precautions.', 'review'),
]


def icon(kind, color):
    g = f'fill="none" stroke="{color}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"'
    paths = {
        'fetch': '<path d="M0 -18 V8 M-10 -2 L0 8 L10 -2 M-18 6 V16 H18 V6"/>',
        'static': '<rect x="-17" y="-20" width="26" height="34" rx="3"/><path d="M-11 -10 H3 M-11 -2 H0"/>'
                  '<circle cx="8" cy="8" r="9"/><path d="M15 15 L22 22"/>',
        'scenario': '<rect x="-18" y="-19" width="8" height="8" rx="2"/><rect x="-18" y="-5" width="8" height="8" rx="2"/>'
                    '<rect x="-18" y="9" width="8" height="8" rx="2"/><path d="M-3 -15 H18 M-3 -1 H18 M-3 13 H12"/>',
        'runtime': '<rect x="-22" y="-16" width="44" height="32" rx="4"/><path d="M-14 -5 L-7 0 L-14 5 M-3 6 H8"/>',
        'review': '<path d="M0 -20 L16 -13 V0 C16 11 9 18 0 22 C-9 18 -16 11 -16 0 V-13 Z"/><path d="M-7 1 L-2 7 L8 -5"/>',
    }
    return f'<g {g}>{paths[kind]}</g>'


def text_width(s, size):
    """Rough width for a sans-serif font; good enough to size pills and chips."""
    narrow = sum(s.count(c) for c in 'iljtf.,:;|!\' ')
    wide = sum(s.count(c) for c in 'MWmw')
    return size * (0.55 * (len(s) - narrow - wide) + 0.3 * narrow + 0.85 * wide)


def frame(w, h, t, body, title, desc):
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-labelledby="t d">
  <title id="t">{escape(title)}</title>
  <desc id="d">{escape(desc)}</desc>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{t['bg0']}"/><stop offset="1" stop-color="{t['bg1']}"/></linearGradient>
    <pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse"><path d="M32 0H0V32" fill="none" stroke="{t['grid']}" stroke-opacity="{t['grid_op']}"/></pattern>
  </defs>
  <rect width="{w}" height="{h}" rx="18" fill="url(#bg)"/>
  <rect width="{w}" height="{h}" rx="18" fill="url(#grid)"/>
  <g font-family="{FONT}">
{body}
  </g>
</svg>
'''


def banner(t):
    w, h = 1200, 300
    b = [f'''    <g transform="translate(140 150)">
      <path d="M0 -94 L76 -64 V-2 C76 48 42 82 0 100 C-42 82 -76 48 -76 -2 V-64 Z" fill="{t['accent']}" fill-opacity="{t['shield_fill_op']}" stroke="{t['accent']}" stroke-width="5" stroke-linejoin="round"/>
      <circle cx="-8" cy="-6" r="32" fill="none" stroke="{t['magnifier']}" stroke-width="9"/>
      <path d="M-22 -6 L-12 5 L8 -16" fill="none" stroke="{t['good']}" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>
      <path d="M16 18 L42 44" stroke="{t['magnifier']}" stroke-width="12" stroke-linecap="round"/>
    </g>
    <text x="270" y="112" fill="{t['title']}" font-size="60" font-weight="700" letter-spacing="-1">plugin-audit</text>
    <text x="272" y="154" fill="{t['text']}" font-size="25">Supply-chain vetting for AI agent extensions</text>
    <text x="272" y="187" fill="{t['muted']}" font-size="17">Claude Code plugins · skills · MCP servers · CLI tools · libraries</text>''']
    x = 270
    for i, c in enumerate(CHIPS):
        cw = text_width(c, 15) + 30
        col = t['good'] if i == len(CHIPS) - 1 else t['accent']
        b.append(f'    <rect x="{x:.0f}" y="214" width="{cw:.0f}" height="34" rx="17" fill="{col}" fill-opacity="0.12" stroke="{col}" stroke-opacity="0.5"/>'
                 f'<text x="{x + cw / 2:.0f}" y="236" fill="{t["title"]}" font-size="15" text-anchor="middle">{escape(c)}</text>')
        x += cw + 10
    return frame(w, h, t, '\n'.join(b), 'plugin-audit',
                 'Supply-chain vetting for AI agent extensions: ' + ', '.join(CHIPS) + '.')


def pipeline(t):
    w, top, row, gap = 920, 70, 108, 22
    h = top + len(STAGES) * row + (len(STAGES) - 1) * gap + 30
    b = [f'    <text x="36" y="44" fill="{t["muted"]}" font-size="15" font-weight="600" letter-spacing="1.5">HOW AN AUDIT RUNS</text>']
    for i, (title, where, l1, l2, ic) in enumerate(STAGES):
        y = top + i * (row + gap)
        last = i == len(STAGES) - 1
        col = t['good'] if last else t['accent']
        stroke = t['good'] if last else t['card']
        sop = 0.45 if last else t['card_stroke_op']
        if t is THEMES['light'] and not last:
            stroke, sop = '#0f172a', t['card_stroke_op']
        b.append(f'    <rect x="24" y="{y}" width="{w - 48}" height="{row}" rx="14" fill="{t["card"]}" fill-opacity="{t["card_op"]}" stroke="{stroke}" stroke-opacity="{sop}"/>')
        b.append(f'    <circle cx="62" cy="{y + row / 2:.0f}" r="16" fill="{col}"/><text x="62" y="{y + row / 2 + 6:.0f}" fill="{t["number_text"]}" font-size="16" font-weight="700" text-anchor="middle">{i + 1}</text>')
        b.append(f'    <g transform="translate(128 {y + row / 2:.0f})">{icon(ic, col)}</g>')
        b.append(f'    <text x="176" y="{y + 40}" fill="{t["title"]}" font-size="22" font-weight="700">{escape(title)}</text>')
        b.append(f'    <text x="176" y="{y + 66}" fill="{t["text"]}" font-size="16">{escape(l1)}</text>')
        b.append(f'    <text x="176" y="{y + 89}" fill="{t["muted"]}" font-size="15">{escape(l2)}</text>')
        hostish = 'HOST' in where
        pc, ptc = (t['host'], t['host_text']) if hostish else (t['accent'], t['accent_text'])
        pw = text_width(where, 12) + 26
        b.append(f'    <rect x="{w - 40 - pw:.0f}" y="{y + 20}" width="{pw:.0f}" height="24" rx="12" fill="{pc}" fill-opacity="0.16"/>'
                 f'<text x="{w - 40 - pw / 2:.0f}" y="{y + 37}" fill="{ptc}" font-size="12" font-weight="700" text-anchor="middle" letter-spacing="0.5">{escape(where)}</text>')
        if not last:
            ay = y + row
            b.append(f'    <path d="M62 {ay + 4} V{ay + gap - 4} M56 {ay + gap - 10} L62 {ay + gap - 4} L68 {ay + gap - 10}" stroke="{t["muted"]}" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>')
    desc = ' '.join(f'{i + 1}. {s[0]} ({s[1]}): {s[2]} {s[3]}' for i, s in enumerate(STAGES))
    return frame(w, h, t, '\n'.join(b), 'How an audit runs', desc)


def badge(label, value, color, name):
    lw, vw = text_width(label, 11) + 14, text_width(value, 11) + 14
    w = lw + vw
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w:.0f}" height="22" viewBox="0 0 {w:.0f} 22" role="img" aria-label="{escape(label)}: {escape(value)}">
  <title>{escape(label)}: {escape(value)}</title>
  <clipPath id="r"><rect width="{w:.0f}" height="22" rx="4"/></clipPath>
  <g clip-path="url(#r)"><rect width="{lw:.0f}" height="22" fill="#334155"/><rect x="{lw:.0f}" width="{vw:.0f}" height="22" fill="{color}"/></g>
  <g fill="#ffffff" font-family="{FONT}" font-size="11" font-weight="600" text-anchor="middle">
    <text x="{lw / 2:.0f}" y="15">{escape(label)}</text><text x="{lw + vw / 2:.0f}" y="15">{escape(value)}</text>
  </g>
</svg>
'''
    with open(os.path.join(OUT, 'badges', name + '.svg'), 'w') as f:
        f.write(svg)


BADGES = [  # label, value, colour, file name
    ('license', 'Apache-2.0', '#0b7bd6', 'license'),
    ('host', 'macOS · Apple silicon', '#475569', 'host'),
    ('sandbox', 'Lima VM · Ubuntu 24.04', '#475569', 'sandbox'),
    ('LLM', 'Claude Code', '#c2410c', 'llm'),
    ('tools audited', '22', '#0369a1', 'audited'),
    ('verdict', '✅ safe to use · 2', '#15803d', 'verdict-safe'),
    ('verdict', '⚠️ use with precautions · 19', '#b45309', 'verdict-precautions'),
    ('verdict', '⛔ do not use · 1', '#b91c1c', 'verdict-do-not-use'),
]

if __name__ == '__main__':
    os.makedirs(os.path.join(OUT, 'badges'), exist_ok=True)
    for name, t in THEMES.items():
        for kind, fn in (('banner', banner), ('pipeline', pipeline)):
            with open(os.path.join(OUT, f'{kind}-{name}.svg'), 'w') as f:
                f.write(fn(t))
    for b in BADGES:
        badge(*b)
    print('written to', OUT)
