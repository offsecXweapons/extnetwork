#!/usr/bin/env python3
import csv
import json
import re
import shlex
import shutil
import subprocess
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, UTC
from pathlib import Path
from typing import List, Dict, Optional

BANNER = """
==============================================================
OffSecXWeapons External Network
==============================================================
"""

PHASES = [
    "Pre-Engagement → PTES Phase 1 + NIST SP 800-115 Planning",
    "Reconnaissance → PTES Phase 2 + MITRE ATT&CK Recon TTPs",
    "Scanning / Validation → PTES Phase 3-4 + OWASP OTG Test Cases",
    "Exploitation (Manual Only) → PTES Phase 5 + MITRE ATT&CK Initial Access TTPs",
    "Severity Scoring → CVSS v4.0",
    "Vulnerability Citation → CVE / NVD",
    "Remediation Guidance → CIS Controls + NIST 800-115",
]

TIMEOUTS = {"ping": 20, "top": 180, "svc": 600, "vuln": 900, "ssl": 240, "headers": 60, "nuclei": 900}
RETRIES = 2
BACKOFF = 1.7


@dataclass
class ToolRun:
    tool: str
    command: str
    returncode: int
    timed_out: bool
    duration_sec: float
    attempts: int
    stdout: str
    stderr: str


@dataclass
class Finding:
    target: str
    title: str
    severity: str
    source: str
    description: str
    remediation: str
    evidence: str = ""
    cves: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)


@dataclass
class TargetResult:
    target: str
    alive: Optional[bool] = None
    open_ports: List[int] = field(default_factory=list)
    tool_runs: List[ToolRun] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    completed: bool = False


def utc_now():
    return datetime.now(UTC)


def esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def sev_rank(s: str) -> int:
    return {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}.get(s, 1)


def parse_targets(raw: str) -> List[str]:
    pts = [x.strip() for x in re.split(r"[,\s]+", raw) if x.strip()]
    ip = r"^(\d{1,3}\.){3}\d{1,3}$"
    cidr = r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$"
    return sorted(set([p for p in pts if re.match(ip, p) or re.match(cidr, p)]))


def cves(text: str) -> List[str]:
    return sorted(set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.I)))


def run_cmd(cmd: str, timeout: int, retries: int = RETRIES, backoff: float = BACKOFF) -> ToolRun:
    attempt = 0
    last = None
    while attempt <= retries:
        attempt += 1
        start = time.time()
        try:
            p = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=timeout)
            return ToolRun(cmd.split()[0], cmd, p.returncode, False, time.time() - start, attempt, p.stdout or "", p.stderr or "")
        except subprocess.TimeoutExpired as e:
            last = ToolRun(cmd.split()[0], cmd, 124, True, time.time() - start, attempt, e.stdout or "", (e.stderr or "") + "\n[TIMEOUT]")
        except Exception as e:
            last = ToolRun(cmd.split()[0] if cmd else "unknown", cmd, 1, False, time.time() - start, attempt, "", f"[ERROR] {e}")
        if attempt <= retries:
            time.sleep(backoff ** attempt)
    return last


def normalize_title(raw: str) -> str:
    t = raw.lower()
    mapping = {
        "telnet": "Telnet exposed externally",
        "tls version 1.1": "TLS 1.1 supported",
        "tls1.1": "TLS 1.1 supported",
        "hsts": "HSTS missing from HTTPS response",
        "self-signed": "SSL certificate cannot be trusted",
        "certificate verify failed": "SSL certificate cannot be trusted",
        "cbc": "CBC cipher suites supported",
    }
    for k, v in mapping.items():
        if k in t:
            return v
    return raw[:180].strip()


def dedupe_findings(findings: List[Finding]) -> List[Finding]:
    merged: Dict[str, Finding] = {}
    for f in findings:
        f.title = normalize_title(f.title)
        key = f"{f.target}|{f.title.lower()}|{','.join(map(str, sorted(set(f.ports))))}"
        if key not in merged:
            merged[key] = f
        else:
            cur = merged[key]
            if sev_rank(f.severity) > sev_rank(cur.severity):
                cur.severity = f.severity
            cur.tags = sorted(set(cur.tags + f.tags))
            cur.cves = sorted(set(cur.cves + f.cves))
            if len(f.evidence) > len(cur.evidence):
                cur.evidence = f.evidence
    return list(merged.values())


def add_tls_header_checks(target: str, port: int, tr: TargetResult):
    scheme = "https"
    hdr = run_cmd(f"curl -k -I --max-time 20 {scheme}://{target}:{port}", TIMEOUTS["headers"])
    tr.tool_runs.append(hdr)
    h = (hdr.stdout + "\n" + hdr.stderr).lower()
    if "strict-transport-security" not in h:
        tr.findings.append(Finding(target, "HSTS missing from HTTPS server", "Medium", "curl-headers",
                                   "No Strict-Transport-Security header observed in HTTPS response headers.",
                                   "Add HSTS header with an appropriate max-age and includeSubDomains where appropriate.",
                                   evidence=hdr.stdout[:2000], tags=["tls", "headers"], ports=[port]))

    ssl = run_cmd(f"nmap -Pn --script ssl-enum-ciphers,ssl-cert -p {port} {target}", TIMEOUTS["ssl"])
    tr.tool_runs.append(ssl)
    s = (ssl.stdout + "\n" + ssl.stderr).lower()
    if "tlsv1.1" in s:
        tr.findings.append(Finding(target, "TLS Version 1.1 Deprecated Protocol", "Medium", "nmap-ssl-enum-ciphers",
                                   "Server appears to support TLS 1.1.",
                                   "Disable TLS 1.1 and older protocols; allow TLS 1.2+.",
                                   evidence=ssl.stdout[:6000], tags=["tls"], ports=[port]))
    if "self-signed" in s or "unable to get local issuer" in s:
        tr.findings.append(Finding(target, "SSL Certificate Cannot Be Trusted", "Medium", "nmap-ssl-cert",
                                   "Certificate trust chain issues detected.",
                                   "Install a certificate chain trusted by major clients.",
                                   evidence=ssl.stdout[:6000], tags=["tls", "certificate"], ports=[port]))
    if "cbc" in s:
        tr.findings.append(Finding(target, "SSL Cipher Block Chaining Cipher Suites Supported", "Info", "nmap-ssl-enum-ciphers",
                                   "CBC-based ciphers are supported.",
                                   "Prefer AEAD cipher suites and disable weak/legacy CBC ciphers where possible.",
                                   evidence=ssl.stdout[:6000], tags=["tls", "cipher"], ports=[port]))


def run_target(target: str, enable_nuclei: bool) -> TargetResult:
    tr = TargetResult(target=target)
    ping = run_cmd(f"nmap -sn {target}", TIMEOUTS["ping"])
    tr.tool_runs.append(ping)
    tr.alive = ("Host is up" in ping.stdout) or ("Nmap scan report for" in ping.stdout)

    top = run_cmd(f"nmap -Pn -p- --min-rate 1000 -T3 {target}", TIMEOUTS["top"])
    tr.tool_runs.append(top)
    tr.open_ports = sorted(set(int(p) for p in re.findall(r"^(\d+)/tcp\s+open", top.stdout, re.M)))
    if tr.open_ports:
        tr.findings.append(Finding(target, "Exposed TCP ports", "Info", "nmap-full-tcp",
                                   f"Detected open TCP ports: {tr.open_ports}",
                                   "Restrict unnecessary internet-exposed services.",
                                   evidence=top.stdout[:4000], tags=["attack-surface"], ports=tr.open_ports))

    svc = run_cmd(f"nmap -Pn -sV -sC -O -p {','.join(map(str, tr.open_ports)) if tr.open_ports else '443'} {target}", TIMEOUTS["svc"])
    tr.tool_runs.append(svc)

    vuln = run_cmd(f"nmap -Pn --script vuln -p {','.join(map(str, tr.open_ports)) if tr.open_ports else '443'} {target}", TIMEOUTS["vuln"])
    tr.tool_runs.append(vuln)
    vc = cves(vuln.stdout + "\n" + vuln.stderr)
    if "VULNERABLE" in vuln.stdout or vc:
        tr.findings.append(Finding(target, "Potential vulnerability indicators", "Medium", "nmap-vuln",
                                   "NSE vulnerability scripts returned potential issues requiring manual confirmation.",
                                   "Validate finding context and patch per vendor advisories.",
                                   evidence=vuln.stdout[:7000], cves=vc, tags=["vulnerability"]))

    for p in [x for x in tr.open_ports if x in {443, 8443, 9443}]:
        add_tls_header_checks(target, p, tr)

    if enable_nuclei and shutil.which("nuclei"):
        nu = run_cmd(f"nuclei -u https://{target} -severity critical,high,medium,low,info -silent", TIMEOUTS["nuclei"])
        tr.tool_runs.append(nu)
        if nu.returncode != 0:
            tr.findings.append(Finding(target, "Nuclei execution error", "Info", "nuclei",
                                       "Nuclei failed to run cleanly for this target.",
                                       "Check nuclei templates/update and runtime flags.",
                                       evidence=(nu.stderr or nu.stdout)[:2000], tags=["tooling"]))
        for ln in [x.strip() for x in nu.stdout.splitlines() if x.strip()][:250]:
            sev = "Info"
            m = re.search(r"\[(critical|high|medium|low|info)\]", ln, flags=re.I)
            if m:
                sev = m.group(1).capitalize()
            tr.findings.append(Finding(target, "Nuclei template result", sev, "nuclei", ln,
                                       "Validate manually before final reporting.",
                                       evidence=ln, cves=cves(ln), tags=["template"]))

    tr.findings = dedupe_findings(tr.findings)
    tr.completed = True
    return tr


def render_html(path: Path, meta: Dict, results: Dict[str, TargetResult], findings: List[Finding]):
    counts = {k: 0 for k in ["Critical", "High", "Medium", "Low", "Info"]}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    nav = "".join([f"<li><a href='#t-{esc(t)}'>{esc(t)}</a></li>" for t in results.keys()])
    sections = []
    for t, tr in results.items():
        tfind = [f for f in findings if f.target == t]
        frows = []
        for f in sorted(tfind, key=lambda x: -sev_rank(x.severity)):
            frows.append(f"""<div class='finding sev-{f.severity.lower()}' data-sev='{f.severity}'>
            <b>{esc(f.severity)}</b> — {esc(f.title)}<br/><small>Source: {esc(f.source)} | Tags: {esc(', '.join(f.tags))}</small>
            <p>{esc(f.description)}</p><p><b>CVE/NVD:</b> {esc(', '.join(f.cves) if f.cves else 'None parsed')}</p>
            <p><b>Remediation:</b> {esc(f.remediation)}</p><details><summary>Evidence</summary><pre>{esc(f.evidence[:9000])}</pre></details></div>""")
        logs = []
        for r in tr.tool_runs:
            badge = "TIMEOUT" if r.timed_out else ("OK" if r.returncode == 0 else "ERR")
            logs.append(f"<details><summary>[{badge}] {esc(r.command)} | attempts={r.attempts} | {r.duration_sec:.1f}s</summary><pre>{esc((r.stdout + chr(10) + r.stderr)[:7000])}</pre></details>")
        sections.append(f"""<section class='card' id='t-{esc(t)}'><h2>{esc(t)}</h2>
        <p><b>Alive:</b> {tr.alive} | <b>Open ports:</b> {esc(', '.join(map(str, tr.open_ports)) if tr.open_ports else 'None')}</p>
        <h3>Findings</h3>{''.join(frows) if frows else '<p>No findings.</p>'}<h3>Execution Logs</h3>{''.join(logs)}</section>""")
    html = f"""<!doctype html><html><head><meta charset='utf-8'><title>OffSecXWeapons External Network</title>
    <style>body{{font-family:Arial;margin:20px;background:#f6f7fb}}.top{{background:#111827;color:#fff;padding:14px;border-radius:8px}}
    .grid{{display:grid;grid-template-columns:240px 1fr;gap:16px}}.side{{background:#fff;padding:12px;border-radius:8px;position:sticky;top:12px;height:fit-content}}
    .card{{background:#fff;padding:14px;border-radius:8px;margin:12px 0;box-shadow:0 1px 4px rgba(0,0,0,.08)}}.finding{{border-left:4px solid #9ca3af;padding:10px;margin:8px 0;background:#fcfcff}}
    .sev-critical{{border-color:#991b1b}} .sev-high{{border-color:#dc2626}} .sev-medium{{border-color:#d97706}} .sev-low{{border-color:#2563eb}} .sev-info{{border-color:#6b7280}}
    pre{{background:#0b1020;color:#e5e7eb;padding:10px;border-radius:6px;max-height:340px;overflow:auto}}</style>
    <script>function filterSev(s){{document.querySelectorAll('.finding').forEach(el=>el.style.display=(s==='ALL'||el.dataset.sev===s)?'block':'none');}}</script>
    </head><body><div class='top'><h1>OffSecXWeapons External Network</h1><p><b>Client:</b> {esc(meta['client'])} | <b>Tester:</b> {esc(meta['tester'])}</p><p><b>Started:</b> {esc(meta['started'])}</p></div>
    <div class='card'><h2>Methodology Mapping</h2>{''.join([f'<div>{esc(p)}</div>' for p in PHASES])}</div>
    <div class='card'>Critical: {counts['Critical']} High: {counts['High']} Medium: {counts['Medium']} Low: {counts['Low']} Info: {counts['Info']}
    <div><button onclick="filterSev('ALL')">All</button><button onclick="filterSev('Critical')">Critical</button><button onclick="filterSev('High')">High</button><button onclick="filterSev('Medium')">Medium</button><button onclick="filterSev('Low')">Low</button><button onclick="filterSev('Info')">Info</button></div></div>
    <div class='grid'><aside class='side'><h3>Targets</h3><ul>{nav}</ul></aside><main>{''.join(sections)}</main></div></body></html>"""
    path.write_text(html, encoding='utf-8')


def main():
    print(BANNER)
    tester = input("Tester name: ").strip() or "Unknown Tester"
    client = input("Client name: ").strip() or "Unknown Client"

    resume = input("Resume previous run? (yes/no): ").strip().lower() in ("yes", "y")
    run_dir = None
    results: Dict[str, TargetResult] = {}

    if resume:
        run_dir = Path(input("Enter existing run directory path: ").strip())
        state_file = run_dir / "state.json"
        if not state_file.exists():
            print("[STOP] state.json not found.")
            return
        state = json.loads(state_file.read_text(encoding='utf-8'))
        meta = state['meta']
        targets = state['targets']
        for t, tr in state['results'].items():
            obj = TargetResult(**{k: v for k, v in tr.items() if k in TargetResult.__dataclass_fields__})
            obj.tool_runs = [ToolRun(**x) for x in tr.get('tool_runs', [])]
            obj.findings = [Finding(**x) for x in tr.get('findings', [])]
            results[t] = obj
    else:
        targets = parse_targets(input("Enter IPs/CIDRs (comma or space separated): ").strip())
        if not targets:
            print("[STOP] No valid targets.")
            return
        run_dir = Path(f"./offsecx_v3_{utc_now().strftime('%Y%m%d_%H%M%S')}")
        run_dir.mkdir(parents=True, exist_ok=True)
        meta = {"tester": tester, "client": client, "started": utc_now().isoformat()}
        results = {t: TargetResult(target=t) for t in targets}

    workers = int((input("Concurrent workers [default 4]: ").strip() or "4"))
    enable_nuclei = input("Enable nuclei if installed? (yes/no): ").strip().lower() in ("yes", "y")
    if not shutil.which('nmap'):
        print('[STOP] nmap is required.')
        return

    pending = [t for t in targets if t not in results or not results[t].completed]
    print(f"Pending targets: {len(pending)} / {len(targets)}")

    def save_state():
        (run_dir / 'state.json').write_text(json.dumps({"meta": meta, "targets": targets, "results": {k: asdict(v) for k, v in results.items()}}, indent=2), encoding='utf-8')

    save_state()

    with ThreadPoolExecutor(max_workers=max(1, min(16, workers))) as ex:
        fut = {ex.submit(run_target, t, enable_nuclei): t for t in pending}
        for f in as_completed(fut):
            t = fut[f]
            try:
                results[t] = f.result()
                print(f"[OK] {t}")
            except Exception as e:
                print(f"[ERR] {t}: {e}")
            save_state()

    all_findings = dedupe_findings([fd for r in results.values() for fd in r.findings])
    all_findings.sort(key=lambda x: (-sev_rank(x.severity), x.target, x.title))

    (run_dir / 'results.json').write_text(json.dumps({"meta": meta, "results": {k: asdict(v) for k, v in results.items()}, "findings": [asdict(f) for f in all_findings]}, indent=2), encoding='utf-8')
    with (run_dir / 'findings.csv').open('w', newline='', encoding='utf-8') as fp:
        w = csv.writer(fp)
        w.writerow(["target", "severity", "title", "source", "cves", "ports", "tags"])
        for f in all_findings:
            w.writerow([f.target, f.severity, f.title, f.source, ';'.join(f.cves), ';'.join(map(str, f.ports)), ';'.join(f.tags)])

    report = run_dir / 'report.html'
    render_html(report, meta, results, all_findings)
    print(f"\nDone.\n- {run_dir / 'state.json'}\n- {run_dir / 'results.json'}\n- {run_dir / 'findings.csv'}\n- {report}")
    try:
        webbrowser.open(f"file://{report.resolve()}")
    except Exception:
        pass


if __name__ == '__main__':
    main()
