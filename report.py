"""
report.py -- renders findings as one self-contained HTML file.

A pure function from the records analyze.py builds to a string of HTML. No
network, no build step, no dependencies: inline CSS and inline JS, so the output
opens from disk, attaches to an email, and can be read end to end by a suspicious
user. That last point matters for a security report -- a page about your leaked
keys should not be fetching anything from anywhere.

EVERYTHING IS ESCAPED, AND THAT IS A SECURITY CONTROL
    This report embeds three kinds of attacker-influenced text: source lines from
    the scanned project, file paths, and model output. Scanning a hostile repo
    whose code contains `<script>` and rendering it unescaped would mean the
    report executes that script when opened -- a scanner that compromises you for
    running it. Every interpolation goes through _esc(). There is no raw-HTML
    path in this module, deliberately. test_report_escaping.py exists to prove
    it, and any new template code must keep that test passing.

THE `fix` FIELD IS TWO DIFFERENT THINGS
    explainer.py's schema says fix is "the corrected code only -- no prose, no
    markdown fences". Engine-answered findings put a sentence of prose there
    instead. They are rendered differently: a code block for one, a paragraph for
    the other, decided by explanation["explained_by"].
"""

import html
import json
import os
import sys
from collections import Counter
from datetime import datetime

SEVERITY_ORDER = ["critical", "high", "medium", "low", "none"]

ENGINE_LABELS = {
    "semgrep": "static analysis",
    "secrets": "credentials",
    "dependencies": "dependencies",
    "config": "configuration",
}


def _esc(value):
    """The only way text enters the document. See the module docstring."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _prose(value):
    """Escape, then render the codebase's ASCII `--` as a real dash.

    Rule and remediation text is authored in ASCII so it reads correctly in a
    terminal. In HTML a bare `--` looks like a typo, and this is a document
    people forward to other people.
    """
    return _esc(value).replace(" -- ", " — ")


CSS = """
:root{
  --bg:#fbfbfa; --panel:#fff; --ink:#1a1a18; --muted:#6b6b66; --line:#e4e4df;
  --crit:#b4231f; --high:#c2600c; --med:#8a6d0b; --low:#4a6b8a; --ok:#2f6b3f;
  --code-bg:#f4f4f1;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#16161a; --panel:#1e1e23; --ink:#e8e8e4; --muted:#9a9a94; --line:#2e2e35;
    --crit:#ff7b72; --high:#ffa657; --med:#e3c96b; --low:#9ac7ea; --ok:#7ee0a0;
    --code-bg:#111116;
  }
}
*{box-sizing:border-box}
body{margin:0;padding:0 1.25rem 4rem;background:var(--bg);color:var(--ink);
  font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:60rem;margin:0 auto}
header{padding:2.5rem 0 1.25rem;border-bottom:1px solid var(--line)}
h1{margin:0 0 .35rem;font-size:1.6rem;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:.9rem}
.sub code{background:var(--code-bg);padding:.1rem .35rem;border-radius:3px}
.tallies{display:flex;flex-wrap:wrap;gap:.5rem;margin:1.25rem 0 0}
.tally{border:1px solid var(--line);background:var(--panel);border-radius:6px;
  padding:.5rem .75rem;min-width:5.5rem}
.tally b{display:block;font-size:1.35rem;line-height:1.2}
.tally span{color:var(--muted);font-size:.75rem;text-transform:uppercase;
  letter-spacing:.04em}
.tally.critical b{color:var(--crit)} .tally.high b{color:var(--high)}
.tally.medium b{color:var(--med)}   .tally.low b{color:var(--low)}
.controls{display:flex;flex-wrap:wrap;gap:.4rem;margin:1.5rem 0 .5rem;
  align-items:center}
.controls .lbl{color:var(--muted);font-size:.8rem;margin-right:.15rem}
button.chip{font:inherit;font-size:.82rem;padding:.3rem .7rem;cursor:pointer;
  border:1px solid var(--line);background:var(--panel);color:var(--muted);
  border-radius:99px}
button.chip[aria-pressed="true"]{background:var(--ink);color:var(--bg);
  border-color:var(--ink)}
.finding{border:1px solid var(--line);background:var(--panel);border-radius:8px;
  margin:.85rem 0;overflow:hidden}
.finding.hidden{display:none}
.fhead{display:flex;gap:.65rem;align-items:baseline;padding:.9rem 1rem;
  cursor:pointer}
.fhead:hover{background:var(--code-bg)}
.badge{font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;
  font-weight:700;padding:.15rem .45rem;border-radius:3px;border:1px solid;
  white-space:nowrap}
.badge.critical{color:var(--crit);border-color:var(--crit)}
.badge.high{color:var(--high);border-color:var(--high)}
.badge.medium{color:var(--med);border-color:var(--med)}
.badge.low{color:var(--low);border-color:var(--low)}
.badge.none{color:var(--muted);border-color:var(--line)}
.ftitle{flex:1;font-weight:600}
.floc{color:var(--muted);font-size:.8rem;font-family:ui-monospace,SFMono-Regular,
  Menlo,monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
  max-width:22rem}
.fbody{padding:0 1rem 1rem;border-top:1px solid var(--line)}
.fbody.collapsed{display:none}
.fbody h4{margin:1rem 0 .3rem;font-size:.72rem;text-transform:uppercase;
  letter-spacing:.06em;color:var(--muted)}
.fbody p{margin:0}
pre{background:var(--code-bg);border:1px solid var(--line);border-radius:5px;
  padding:.7rem .85rem;overflow-x:auto;margin:.35rem 0 0;
  font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}
.meta{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.9rem}
.pill{font-size:.72rem;color:var(--muted);border:1px solid var(--line);
  border-radius:99px;padding:.15rem .55rem;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.copy{font:inherit;font-size:.72rem;padding:.2rem .55rem;cursor:pointer;
  border:1px solid var(--line);background:var(--panel);color:var(--muted);
  border-radius:4px;margin-top:.45rem}
.copy:hover{color:var(--ink)}
section h2{font-size:1.05rem;margin:2.5rem 0 .25rem}
section .note{color:var(--muted);font-size:.85rem;margin:0 0 .5rem}
.empty{border:1px dashed var(--line);border-radius:8px;padding:2rem;
  text-align:center;color:var(--muted)}
.empty b{color:var(--ok)}
footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--line);
  color:var(--muted);font-size:.8rem}
#nomatch{display:none;color:var(--muted);padding:1.5rem 0}
@media (max-width:46rem){
  .fhead{flex-wrap:wrap;gap:.4rem}
  .ftitle{flex:1 1 100%;order:2}
  .floc{order:3;flex:1 1 100%;max-width:100%}
}
"""

JS = """
(function(){
  var filters = {severity:new Set(), engine:new Set()};

  function apply(){
    var shown = 0;
    document.querySelectorAll('.finding').forEach(function(el){
      var sevOk = !filters.severity.size || filters.severity.has(el.dataset.severity);
      var engOk = !filters.engine.size || filters.engine.has(el.dataset.engine);
      var vis = sevOk && engOk;
      el.classList.toggle('hidden', !vis);
      if (vis) shown++;
    });
    document.querySelectorAll('section[data-group]').forEach(function(s){
      var any = s.querySelectorAll('.finding:not(.hidden)').length;
      s.style.display = any ? '' : 'none';
    });
    document.getElementById('nomatch').style.display = shown ? 'none' : 'block';
  }

  document.querySelectorAll('button.chip').forEach(function(btn){
    btn.addEventListener('click', function(){
      var on = btn.getAttribute('aria-pressed') === 'true';
      btn.setAttribute('aria-pressed', on ? 'false' : 'true');
      var set = filters[btn.dataset.kind];
      if (on) { set.delete(btn.dataset.value); } else { set.add(btn.dataset.value); }
      apply();
    });
  });

  document.querySelectorAll('.fhead').forEach(function(head){
    head.addEventListener('click', function(){
      head.nextElementSibling.classList.toggle('collapsed');
    });
  });

  // navigator.clipboard needs a secure context, and file:// is not one in most
  // browsers -- so the textarea path is the one that actually runs here, not a
  // fallback for exotic cases.
  document.querySelectorAll('.copy').forEach(function(btn){
    btn.addEventListener('click', function(ev){
      ev.stopPropagation();
      var text = btn.previousElementSibling.innerText;
      var done = function(){
        var was = btn.textContent; btn.textContent = 'copied';
        setTimeout(function(){ btn.textContent = was; }, 1200);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, function(){});
        return;
      }
      var ta = document.createElement('textarea');
      ta.value = text; ta.setAttribute('readonly','');
      ta.style.position='fixed'; ta.style.opacity='0';
      document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); done(); } catch(e) {}
      document.body.removeChild(ta);
    });
  });
})();
"""


def _tally(records):
    counts = Counter(r["explanation"].get("severity", "none") for r in records)
    parts = []
    for severity in SEVERITY_ORDER[:-1]:
        parts.append(
            f'<div class="tally {severity}"><b>{counts.get(severity, 0)}</b>'
            f"<span>{severity}</span></div>"
        )
    parts.append(
        f'<div class="tally"><b>{len(records)}</b><span>total</span></div>'
    )
    return "".join(parts)


def _chips(records):
    severities = [s for s in SEVERITY_ORDER
                  if any(r["explanation"].get("severity") == s for r in records)]
    engines = sorted({r.get("engine", "semgrep") for r in records})

    out = ['<div class="controls"><span class="lbl">severity</span>']
    for severity in severities:
        out.append(f'<button class="chip" aria-pressed="false" data-kind="severity" '
                   f'data-value="{_esc(severity)}">{_esc(severity)}</button>')
    out.append('</div><div class="controls"><span class="lbl">source</span>')
    for engine in engines:
        label = ENGINE_LABELS.get(engine, engine)
        out.append(f'<button class="chip" aria-pressed="false" data-kind="engine" '
                   f'data-value="{_esc(engine)}">{_esc(label)}</button>')
    out.append("</div>")
    return "".join(out)


def _pills(record):
    """Engine-specific detail, rendered as small monospace tags."""
    meta = record.get("metadata") or {}
    pills = [f"{record.get('engine', 'semgrep')}"]

    if meta.get("cve_ids"):
        pills.extend(meta["cve_ids"][:4])
        if len(meta["cve_ids"]) > 4:
            pills.append(f"+{len(meta['cve_ids']) - 4} more")
    if meta.get("cvss_score") is not None:
        pills.append(f"CVSS {meta['cvss_score']}")
    if meta.get("fixed_version"):
        pills.append(f"fixed in {meta['fixed_version']}")
    if meta.get("redacted"):
        pills.append(meta["redacted"])
    if meta.get("exposure"):
        pills.append(meta["exposure"])
    if meta.get("confidence") == "medium":
        pills.append("medium confidence")
    if record.get("also_matched"):
        pills.append(f"+{len(record['also_matched'])} other rule(s) here")

    return "".join(f'<span class="pill">{_esc(p)}</span>' for p in pills)


def _finding(record):
    explanation = record.get("explanation") or {}
    severity = explanation.get("severity", "none")
    engine = record.get("engine", "semgrep")
    fix = explanation.get("fix") or ""

    # Engine findings put prose in `fix`; the explainer puts bare code there.
    if explanation.get("explained_by") == "engine":
        fix_html = f"<p>{_prose(fix)}</p>" if fix else ""
    elif fix:
        fix_html = (f"<pre>{_esc(fix)}</pre>"
                    '<button class="copy" type="button">copy fix</button>')
    else:
        fix_html = ""

    scenario = explanation.get("attacker_scenario") or ""
    title = explanation.get("what_it_is") or record.get("check_id", "Finding")

    return (
        f'<article class="finding" data-severity="{_esc(severity)}" '
        f'data-engine="{_esc(engine)}">'
        f'<div class="fhead">'
        f'<span class="badge {_esc(severity)}">{_esc(severity)}</span>'
        f'<span class="ftitle">{_prose(title)}</span>'
        f'<span class="floc">{_esc(record.get("path", "?"))}'
        f':{_esc(record.get("line", "?"))}</span>'
        f"</div>"
        f'<div class="fbody collapsed">'
        # A failed finding has no scenario and no fix, so without this the
        # "review these by hand" section gives the reader nothing to act on.
        + (f"<h4>Why this could not be explained</h4><p>{_prose(record['error'])}</p>"
           if record.get("error") else "")
        + (f"<h4>Why it matters</h4><p>{_prose(scenario)}</p>" if scenario else "")
        + (f"<h4>Fix</h4>{fix_html}" if fix_html else "")
        + (f'<h4>Rule</h4><p><span class="pill">'
           f'{_esc(record.get("check_id", ""))}</span></p>')
        + f'<div class="meta">{_pills(record)}</div>'
        + "</div></article>"
    )


def _section(title, note, records, group):
    if not records:
        return ""
    body = "".join(_finding(r) for r in records)
    return (f'<section data-group="{_esc(group)}"><h2>{_esc(title)}</h2>'
            f'<p class="note">{_esc(note)}</p>{body}</section>')


def render(results, target, scan_count=None, deduped_count=None):
    """Return a complete HTML document for these findings."""
    real = [r for r in results
            if r["explanation"].get("is_real_vulnerability") and not r.get("error")]
    dismissed = [r for r in results
                 if not r["explanation"].get("is_real_vulnerability")
                 and not r.get("error")]
    failed = [r for r in results if r.get("error")]

    real.sort(key=lambda r: (
        SEVERITY_ORDER.index(r["explanation"].get("severity", "none"))
        if r["explanation"].get("severity") in SEVERITY_ORDER else 9,
        r.get("path", ""),
        r.get("line", 0),
    ))

    generated = datetime.now().strftime("%Y-%m-%d %H:%M")
    counted = ""
    if scan_count is not None and deduped_count is not None:
        counted = f" · {scan_count} raw findings across {deduped_count} locations"

    if real:
        main = _section(
            "Findings", "Worst first. Click any row to expand.", real, "real")
        empty = ""
    else:
        main = ""
        empty = ('<div class="empty"><b>No confirmed findings.</b><br>'
                 "That means these rules matched nothing here — not that the "
                 "project is secure.</div>")

    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>VibeSec report — {_esc(target)}</title>"
        f"<style>{CSS}</style></head><body><div class=\"wrap\">"
        f"<header><h1>Security audit</h1>"
        f'<div class="sub"><code>{_esc(target)}</code> · {_esc(generated)}'
        f"{_esc(counted)}</div>"
        f'<div class="tallies">{_tally(real)}</div>'
        f"</header>"
        f"{_chips(results) if results else ''}"
        f'<div id="nomatch">No findings match the selected filters.</div>'
        f"{empty}{main}"
        + _section(
            "Dismissed", "Claude found no concrete attack against these. Worth "
            "spot-checking — a wrong dismissal is a vulnerability you were told "
            "to ignore.", dismissed, "dismissed")
        + _section(
            "Could not be explained", "Flagged by a scanner, but the explanation "
            "failed. These are NOT cleared — review them by hand.", failed, "failed")
        + "<footer>Generated by VibeSec. Credentials are shown redacted. "
          "This file makes no network requests.</footer>"
        + f"</div><script>{JS}</script></body></html>"
    )


def write(results, target, out_path, scan_count=None, deduped_count=None):
    """Render and write the report. Returns the path written."""
    document = render(results, target, scan_count, deduped_count)
    directory = os.path.dirname(os.path.abspath(out_path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write(document)
    return out_path


if __name__ == "__main__":
    # Renders straight from `analyze.py --json` output, so the report layer can be
    # tested and iterated on without re-running a scan.
    if len(sys.argv) < 3:
        print("usage: python report.py <findings.json> <out.html> [target-label]")
        sys.exit(1)

    with open(sys.argv[1], "r", encoding="utf-8") as handle:
        records = json.load(handle)

    label = sys.argv[3] if len(sys.argv) > 3 else sys.argv[1]
    destination = write(records, label, sys.argv[2])
    print(f"wrote {destination} ({len(records)} finding(s))")
