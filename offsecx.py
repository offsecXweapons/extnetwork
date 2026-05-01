#!/usr/bin/env python3
import csv
import json
import argparse
import re
import shlex
import shutil
import subprocess
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

BANNER = "OffSecXWeapons External Network"
UTC = timezone.utc

TIMEOUTS = {
    "ping": 15,
    "ports": 900,
    "service": 900,
    "vuln": 900,
    "ssl_nmap": 300,
    "curl_headers": 30,
    "nuclei": 300,
    "optional": 300,
}
RETRIES = 2
BACKOFF = 1.6

HTTP_PORTS = {80, 8080, 8000, 8888}
HTTPS_PORTS = {443, 8443, 9443, 10443}


@dataclass
class ToolRun:
    tool: str
    command: str
    status: str
    returncode: int
    timed_out: bool
    attempts: int
    duration_sec: float
    stdout: str
    stderr: str


@dataclass
class Finding:
    target: str
    title: str
    severity: str
    description: str
    sources: Set[str] = field(default_factory=set)
    evidence: List[str] = field(default_factory=list)
    cves: Set[str] = field(default_factory=set)
    tags: List[str] = field(default_factory=list)
    ports: Set[int] = field(default_factory=set)
    protocols: Set[str] = field(default_factory=set)
    urls: Set[str] = field(default_factory=set)


@dataclass
class TargetResult:
    target: str
    alive: Optional[bool] = None
    hostnames: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    tool_runs: List[ToolRun] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    completed: bool = False


def now_utc() -> datetime:
    return datetime.now(UTC)


def parse_targets(raw: str) -> List[str]:
    parts = [x.strip() for x in re.split(r"[,\s]+", raw) if x.strip()]
    ip = r"^(\d{1,3}\.){3}\d{1,3}$"
    cidr = r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$"
    return sorted(set([p for p in parts if re.match(ip, p) or re.match(cidr, p)]))


def extract_cves(text: str) -> Set[str]:
    return set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text or "", flags=re.I))


def run_cmd(cmd: str, timeout: int, retries: int = RETRIES, backoff: float = BACKOFF, shell: bool = False) -> ToolRun:
    last = None
    for attempt in range(1, retries + 2):
        t0 = time.time()
        try:
            proc = subprocess.run(cmd if shell else shlex.split(cmd), capture_output=True, text=True, timeout=timeout, shell=shell)
            return ToolRun(cmd.split()[0], cmd, "OK" if proc.returncode == 0 else "ERR", proc.returncode, False, attempt, time.time() - t0, proc.stdout or "", proc.stderr or "")
        except subprocess.TimeoutExpired as e:
            last = ToolRun(cmd.split()[0], cmd, "TIMEOUT", 124, True, attempt, time.time() - t0, e.stdout or "", (e.stderr or "") + "\n[TIMEOUT]")
        except Exception as e:
            last = ToolRun(cmd.split()[0] if cmd else "unknown", cmd, "ERR", 1, False, attempt, time.time() - t0, "", f"{e}")
        if attempt <= retries:
            time.sleep(backoff ** attempt)
    return last


def add_finding(tr: TargetResult, finding: Finding):
    tr.findings.append(finding)


def normalize_title(title: str) -> str:
    t = title.lower()
    checks = [
        ("hsts", "HSTS missing from HTTPS server"),
        ("tls 1.0", "TLS 1.0 supported"),
        ("tlsv1.0", "TLS 1.0 supported"),
        ("tls 1.1", "TLS 1.1 supported"),
        ("tlsv1.1", "TLS 1.1 supported"),
        ("self-signed", "Self-signed certificate"),
        ("cannot be trusted", "SSL certificate cannot be trusted"),
        ("invalid certificate chain", "Invalid certificate chain"),
        ("cbc", "Weak CBC ciphers supported"),
        ("certificate expiring", "Certificate expiring soon"),
        ("alpn", "ALPN information"),
    ]
    for k, v in checks:
        if k in t:
            return v
    return title.strip()[:180]


def merge_findings(findings: List[Finding]) -> List[Finding]:
    merged: Dict[str, Finding] = {}
    sev_rank = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
    for f in findings:
        f.title = normalize_title(f.title)
        key = f"{f.target}|{f.title}"
        if key not in merged:
            merged[key] = f
        else:
            cur = merged[key]
            if sev_rank.get(f.severity, 1) > sev_rank.get(cur.severity, 1):
                cur.severity = f.severity
            cur.sources |= f.sources
            cur.cves |= f.cves
            cur.ports |= f.ports
            cur.protocols |= f.protocols
            cur.urls |= f.urls
            cur.evidence.extend(f.evidence)
    return list(merged.values())


def web_urls(target: str, ports: List[int]) -> List[Tuple[str, int]]:
    out = []
    for p in ports:
        if p in HTTP_PORTS:
            out.append((f"http://{target}:{p}", p))
        if p in HTTPS_PORTS:
            out.append((f"https://{target}:{p}", p))
    return out


def scan_target(target: str, opts: Dict[str, bool]) -> TargetResult:
    tr = TargetResult(target=target)

    ping = run_cmd(f"nmap -sn {target}", TIMEOUTS["ping"])
    tr.tool_runs.append(ping)
    tr.alive = "Host is up" in ping.stdout

    ports = run_cmd(f"nmap -Pn -n -p- --min-rate 800 -T3 {target}", TIMEOUTS["ports"])
    tr.tool_runs.append(ports)
    tr.open_ports = sorted(set(int(p) for p in re.findall(r"^(\d+)/tcp\s+open", ports.stdout, flags=re.M)))
    if tr.open_ports:
        add_finding(tr, Finding(target, "Service detection", "Info", f"Open ports discovered: {tr.open_ports}", {"nmap"}, [ports.stdout[:2000]], ports=set(tr.open_ports)))

    pstr = ",".join(map(str, tr.open_ports)) if tr.open_ports else "443"
    svc = run_cmd(f"nmap -Pn -n -sV -sC -O -p {pstr} {target}", TIMEOUTS["service"])
    tr.tool_runs.append(svc)
    s = (svc.stdout + "\n" + svc.stderr)

    if "OS details" in s or "OS guesses" in s:
        add_finding(tr, Finding(target, "OS fingerprinting if available", "Info", "OS fingerprint data identified.", {"nmap"}, [s[:2000]]))
    if "tcp timestamp" in s.lower():
        add_finding(tr, Finding(target, "TCP/IP timestamps supported if detected", "Info", "TCP timestamp behavior observed.", {"nmap"}, [s[:1200]]))
    for hn in re.findall(r"Nmap scan report for\s+(.+)", s):
        tr.hostnames.append(hn.strip())
    if tr.hostnames:
        add_finding(tr, Finding(target, "Hostname / reverse DNS / FQDN data if available", "Info", "Hostname data identified in scan output.", {"nmap"}, ["; ".join(tr.hostnames)]))

    vuln = run_cmd(f"nmap -Pn -n --script vuln -p {pstr} {target}", TIMEOUTS["vuln"])
    tr.tool_runs.append(vuln)
    vtxt = vuln.stdout + "\n" + vuln.stderr
    cve_set = extract_cves(vtxt)
    if "VULNERABLE" in vuln.stdout or cve_set:
        add_finding(tr, Finding(target, "Vulnerability indicators", "Medium", "Potential vulnerabilities from NSE vuln scripts.", {"nmap-vuln"}, [vuln.stdout[:3000]], cve_set))

    for url, port in web_urls(target, tr.open_ports):
        hdr = run_cmd(f"curl -k -I --max-time 20 {url}", TIMEOUTS["curl_headers"])
        tr.tool_runs.append(hdr)
        htxt = (hdr.stdout + "\n" + hdr.stderr).lower()
        add_finding(tr, Finding(target, "HTTP security header observations", "Info", f"Header sample captured for {url}", {"curl"}, [hdr.stdout[:1200]], ports={port}, urls={url}))
        if url.startswith("https://") and "strict-transport-security" not in htxt:
            add_finding(tr, Finding(target, "HSTS missing from HTTPS server", "Medium", f"No HSTS header in response from {url}", {"curl"}, [hdr.stdout[:1200]], ports={port}, urls={url}, protocols={"https"}))

        ssl_nm = run_cmd(f"nmap -Pn -n --script ssl-enum-ciphers,ssl-cert,ssl-dh-params -p {port} {target}", TIMEOUTS["ssl_nmap"])
        tr.tool_runs.append(ssl_nm)
        stxt = (ssl_nm.stdout + "\n" + ssl_nm.stderr).lower()
        add_finding(tr, Finding(target, "TLS versions supported", "Info", f"TLS/cert script output collected for {url}", {"nmap-ssl"}, [ssl_nm.stdout[:2800]], ports={port}, urls={url}, protocols={"https"}))
        add_finding(tr, Finding(target, "certificate information", "Info", "Certificate metadata captured.", {"nmap-ssl"}, [ssl_nm.stdout[:1800]], ports={port}, urls={url}))
        add_finding(tr, Finding(target, "cipher suite information", "Info", "Cipher suite metadata captured.", {"nmap-ssl"}, [ssl_nm.stdout[:1800]], ports={port}, urls={url}))
        if "tlsv1.0" in stxt:
            add_finding(tr, Finding(target, "TLS 1.0 supported", "Medium", f"TLS 1.0 appears enabled on {url}", {"nmap-ssl"}, [ssl_nm.stdout[:1800]], ports={port}, urls={url}))
        if "tlsv1.1" in stxt:
            add_finding(tr, Finding(target, "TLS 1.1 supported", "Medium", f"TLS 1.1 appears enabled on {url}", {"nmap-ssl"}, [ssl_nm.stdout[:1800]], ports={port}, urls={url}))
        if "self-signed" in stxt:
            add_finding(tr, Finding(target, "self-signed certificate", "Medium", f"Self-signed certificate on {url}", {"nmap-ssl"}, [ssl_nm.stdout[:1800]], ports={port}, urls={url}))
        if "unable to get local issuer" in stxt or "certificate chain" in stxt:
            add_finding(tr, Finding(target, "invalid certificate chain", "Medium", f"Certificate chain issues observed on {url}", {"nmap-ssl"}, [ssl_nm.stdout[:1800]], ports={port}, urls={url}))
        if "not valid after" in stxt or "expires" in stxt:
            add_finding(tr, Finding(target, "certificate expiring soon", "Info", "Certificate expiration metadata observed.", {"nmap-ssl"}, [ssl_nm.stdout[:1800]], ports={port}, urls={url}))
        if "cbc" in stxt:
            add_finding(tr, Finding(target, "weak cbc ciphers", "Info", f"CBC ciphers listed for {url}", {"nmap-ssl"}, [ssl_nm.stdout[:1800]], ports={port}, urls={url}))

    if opts.get("traceroute") and shutil.which("traceroute"):
        trc = run_cmd(f"traceroute -n -m 10 {target}", TIMEOUTS["optional"])
        tr.tool_runs.append(trc)
        if trc.stdout.strip():
            add_finding(tr, Finding(target, "Traceroute information if available", "Info", "Traceroute path captured.", {"traceroute"}, [trc.stdout[:1200]]))

    # Optional tools
    if opts.get("whatweb") and shutil.which("whatweb"):
        for url, port in web_urls(target, tr.open_ports):
            ww = run_cmd(f"whatweb -a 1 {url}", TIMEOUTS["optional"])
            tr.tool_runs.append(ww)
            if ww.stdout.strip():
                add_finding(tr, Finding(target, "exposed HTTPS metadata", "Info", f"Technology metadata discovered at {url}", {"whatweb"}, [ww.stdout[:1000]], ports={port}, urls={url}))

    if opts.get("nikto") and shutil.which("nikto"):
        for url, port in web_urls(target, tr.open_ports):
            nk = run_cmd(f"nikto -h {url}", TIMEOUTS["optional"])
            tr.tool_runs.append(nk)
            if nk.stdout.strip():
                add_finding(tr, Finding(target, "Service detection", "Info", f"Nikto observations for {url}", {"nikto"}, [nk.stdout[:1200]], ports={port}, urls={url}))

    if opts.get("sslscan") and shutil.which("sslscan"):
        for p in [x for x in tr.open_ports if x in HTTPS_PORTS]:
            ss = run_cmd(f"sslscan {target}:{p}", TIMEOUTS["optional"])
            tr.tool_runs.append(ss)
            if "tlsv1.0" in (ss.stdout + ss.stderr).lower():
                add_finding(tr, Finding(target, "TLS 1.0 supported", "Medium", f"sslscan reports TLS 1.0 on {target}:{p}", {"sslscan"}, [ss.stdout[:1800]], ports={p}))
            if "tlsv1.1" in (ss.stdout + ss.stderr).lower():
                add_finding(tr, Finding(target, "TLS 1.1 supported", "Medium", f"sslscan reports TLS 1.1 on {target}:{p}", {"sslscan"}, [ss.stdout[:1800]], ports={p}))
            if "alpn" in (ss.stdout + ss.stderr).lower():
                add_finding(tr, Finding(target, "ALPN information if available", "Info", "ALPN output captured.", {"sslscan"}, [ss.stdout[:1200]], ports={p}))

    if opts.get("testssl") and (shutil.which("testssl.sh") or Path("./testssl.sh/testssl.sh").exists()):
        tsbin = "testssl.sh" if shutil.which("testssl.sh") else "./testssl.sh/testssl.sh"
        for p in [x for x in tr.open_ports if x in HTTPS_PORTS]:
            ts = run_cmd(f"{tsbin} -U --warnings off {target}:{p}", TIMEOUTS["optional"])
            tr.tool_runs.append(ts)
            ttxt = (ts.stdout + "\n" + ts.stderr).lower()
            if "tls 1" in ttxt:
                add_finding(tr, Finding(target, "supported TLS versions", "Info", f"testssl protocol output for {target}:{p}", {"testssl.sh"}, [ts.stdout[:1800]], ports={p}))
            if "chain" in ttxt:
                add_finding(tr, Finding(target, "SSL certificate cannot be trusted", "Medium", "Potential trust/chain issue from testssl output.", {"testssl.sh"}, [ts.stdout[:1800]], ports={p}))

    if opts.get("nuclei") and shutil.which("nuclei"):
        for url, port in web_urls(target, tr.open_ports):
            nu = run_cmd(f"nuclei -u {url} -severity critical,high,medium,low,info -silent", TIMEOUTS["nuclei"])
            tr.tool_runs.append(nu)
            if nu.status != "OK":
                add_finding(tr, Finding(target, "Nuclei execution error", "Info", f"nuclei failed for {url}", {"nuclei"}, [nu.stderr[:1200]], ports={port}, urls={url}))
            for ln in [x.strip() for x in nu.stdout.splitlines() if x.strip()][:200]:
                sev = "Info"
                m = re.search(r"\[(critical|high|medium|low|info)\]", ln, re.I)
                if m:
                    sev = m.group(1).capitalize()
                add_finding(tr, Finding(target, "Nuclei template result", sev, ln, {"nuclei"}, [ln], extract_cves(ln), ports={port}, urls={url}))

    # Nessus-style informational catch-all
    add_finding(tr, Finding(target, "Device/service type", "Info", "Derived from service fingerprinting output.", {"nmap"}, [svc.stdout[:1000]]))

    tr.findings = merge_findings(tr.findings)
    tr.completed = True
    return tr


def html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def finding_tags(f: Finding) -> List[str]:
    return getattr(f, "tags", []) or []


def is_tls_related_finding(f: Finding) -> bool:
    text = " ".join([
        getattr(f, "title", "") or "",
        getattr(f, "description", "") or "",
        " ".join(getattr(f, "sources", []) or []),
        " ".join(finding_tags(f)),
    ]).lower()
    return any(k in text for k in ["tls", "ssl", "certificate", "cipher", "hsts", "https"])


def render_report(path: Path, meta: Dict, results: Dict[str, TargetResult], findings: List[Finding], missing_optional: List[str]):
    counts = {k: 0 for k in ["Critical", "High", "Medium", "Low", "Info"]}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    rows = []
    for f in sorted(findings, key=lambda x: (-{"Critical":5,"High":4,"Medium":3,"Low":2,"Info":1}[x.severity], x.target, x.title)):
        rows.append(f"<tr data-sev='{f.severity}'><td>{html_escape(f.target)}</td><td>{html_escape(f.severity)}</td><td>{html_escape(f.title)}</td><td>{html_escape(', '.join(sorted(f.sources)))}</td><td>{html_escape(f.description)}</td></tr>")

    sections = []
    for t, tr in results.items():
        runs_html_parts = []
        for r in tr.tool_runs:
            combined = (r.stdout + "\n" + r.stderr)[:3000]
            runs_html_parts.append(
                f"<details><summary>[{r.status}] {html_escape(r.command)}</summary>"
                f"<div>return={r.returncode} attempts={r.attempts} runtime={r.duration_sec:.1f}s</div>"
                f"<pre>{html_escape(combined)}</pre></details>"
            )
        runs_html = "".join(runs_html_parts)
        tls_findings = [f for f in tr.findings if is_tls_related_finding(f)]
        services = ", ".join(map(str, tr.open_ports)) if tr.open_ports else "None"
        sections.append(f"""
        <section id='host-{html_escape(t)}' class='card'>
          <h2>{html_escape(t)}</h2>
          <p><b>Alive:</b> {tr.alive} | <b>Open Ports:</b> {html_escape(services)}</p>
          <h3>Services</h3><p>{html_escape(services)}</p>
          <h3>TLS/Certificate</h3><ul>{''.join([f"<li>{html_escape(x.title)} ({x.severity})</li>" for x in tls_findings]) or '<li>No TLS-specific findings.</li>'}</ul>
          <h3>Tool Output</h3>{runs_html}
        </section>
        """)

    html = f"""<!doctype html><html><head><meta charset='utf-8'><title>OffSecXWeapons External Network</title>
    <style>body{{font-family:Arial;margin:20px;background:#f7f8fb}}.card{{background:#fff;border-radius:8px;padding:12px;margin:12px 0;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
    table{{width:100%;border-collapse:collapse}}th,td{{border:1px solid #ddd;padding:6px}}pre{{white-space:pre-wrap;background:#111;color:#eee;padding:8px}}</style>
    <script>
      function filterSev(s){{document.querySelectorAll('tbody tr').forEach(r=>r.style.display=(s==='ALL'||r.dataset.sev===s)?'':'none')}}
      function searchRows(){{let q=document.getElementById('q').value.toLowerCase();document.querySelectorAll('tbody tr').forEach(r=>r.style.display=r.innerText.toLowerCase().includes(q)?'':'none')}}
    </script></head><body>
    <h1>OffSecXWeapons External Network</h1>
    <div class='card'><b>Client:</b> {html_escape(meta['client'])} | <b>Tester:</b> {html_escape(meta['tester'])} | <b>Started:</b> {html_escape(meta['started'])}</div>
    <div class='card'><h2>Dashboard</h2><p>Critical {counts['Critical']} | High {counts['High']} | Medium {counts['Medium']} | Low {counts['Low']} | Info {counts['Info']}</p>
    <input id='q' onkeyup='searchRows()' placeholder='Search findings...'/> 
    <button onclick="filterSev('ALL')">All</button><button onclick="filterSev('Critical')">Critical</button><button onclick="filterSev('High')">High</button><button onclick="filterSev('Medium')">Medium</button><button onclick="filterSev('Low')">Low</button><button onclick="filterSev('Info')">Info</button></div>
    <div class='card'><h2>Missing/Skipped Optional Tools</h2><ul>{''.join([f'<li>{html_escape(x)}</li>' for x in missing_optional]) or '<li>None</li>'}</ul></div>
    <div class='card'><h2>Target Navigation</h2><ul>{''.join([f"<li><a href='#host-{html_escape(t)}'>{html_escape(t)}</a></li>" for t in results.keys()])}</ul></div>
    <div class='card'><h2>Findings Table</h2><table><thead><tr><th>Target</th><th>Severity</th><th>Title</th><th>Sources</th><th>Description</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
    {''.join(sections)}
    <div class='card'><h2>Manual validation notes</h2><ol><li>Validate medium+ findings manually against service versions and configs.</li><li>Do not perform exploitation in this automation run.</li><li>Retest after remediation.</li></ol></div>
    </body></html>"""
    path.write_text(html, encoding="utf-8")


def _self_check_render_compat() -> None:
    tmp = Path(".offsecx_render_check.html")
    legacy = Finding(target="127.0.0.1", title="SSL certificate cannot be trusted", severity="Medium", description="legacy finding without tags")
    tr = TargetResult(target="127.0.0.1", alive=True, open_ports=[443], findings=[legacy], completed=True)
    render_report(tmp, {"client": "selfcheck", "tester": "selfcheck", "started": now_utc().isoformat()}, {"127.0.0.1": tr}, [legacy], [])
    tmp.unlink(missing_ok=True)


def main():
    print(BANNER)
    tester = input("Tester name: ").strip() or "Unknown Tester"
    client = input("Client name: ").strip() or "Unknown Client"
    resume = input("Resume previous run? yes/no: ").strip().lower() in ("yes", "y")

    results: Dict[str, TargetResult] = {}
    if resume:
        run_dir = Path(input("Existing run directory: ").strip())
        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        targets = state["targets"]
        meta = state["meta"]
        for t, r in state["results"].items():
            tr = TargetResult(target=t, alive=r.get("alive"), hostnames=r.get("hostnames", []), open_ports=r.get("open_ports", []), completed=r.get("completed", False))
            tr.tool_runs = [ToolRun(**x) for x in r.get("tool_runs", [])]
            tr.findings = [Finding(target=x["target"], title=x["title"], severity=x["severity"], description=x["description"], sources=set(x.get("sources", [])), evidence=x.get("evidence", []), cves=set(x.get("cves", [])), tags=x.get("tags", []), ports=set(x.get("ports", [])), protocols=set(x.get("protocols", [])), urls=set(x.get("urls", []))) for x in r.get("findings", [])]
            results[t] = tr
    else:
        targets = parse_targets(input("IPs/CIDRs (comma or space separated): ").strip())
        run_dir = Path(f"offsecx_v3_{now_utc().strftime('%Y%m%d_%H%M%S')}")
        run_dir.mkdir(parents=True, exist_ok=True)
        meta = {"tester": tester, "client": client, "started": now_utc().isoformat()}
        results = {t: TargetResult(target=t) for t in targets}

    workers = int((input("Concurrent workers [default 4]: ").strip() or "4"))
    opts = {
        "nuclei": input("Enable nuclei if installed? yes/no: ").strip().lower() in ("yes", "y"),
        "testssl": input("Enable testssl.sh if installed? yes/no: ").strip().lower() in ("yes", "y"),
        "sslscan": input("Enable sslscan if installed? yes/no: ").strip().lower() in ("yes", "y"),
        "nikto": input("Enable nikto if installed? yes/no: ").strip().lower() in ("yes", "y"),
        "whatweb": input("Enable whatweb if installed? yes/no: ").strip().lower() in ("yes", "y"),
        "traceroute": input("Enable traceroute if installed? yes/no: ").strip().lower() in ("yes", "y"),
    }

    if not shutil.which("nmap"):
        raise SystemExit("[STOP] nmap is required")

    missing_optional = [x for x in ["nuclei", "testssl.sh", "sslscan", "nikto", "whatweb", "traceroute"] if not (shutil.which(x) or (x == "testssl.sh" and Path("./testssl.sh/testssl.sh").exists()))]

    def save_state():
        payload = {
            "meta": meta,
            "targets": targets,
            "results": {t: {
                "target": r.target,
                "alive": r.alive,
                "hostnames": r.hostnames,
                "open_ports": r.open_ports,
                "tool_runs": [asdict(x) for x in r.tool_runs],
                "findings": [{**asdict(f), "sources": sorted(f.sources), "cves": sorted(f.cves), "ports": sorted(f.ports), "protocols": sorted(f.protocols), "urls": sorted(f.urls)} for f in r.findings],
                "completed": r.completed,
            } for t, r in results.items()}
        }
        (run_dir / "state.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    save_state()
    pending = [t for t, r in results.items() if not r.completed]
    with ThreadPoolExecutor(max_workers=max(1, min(16, workers))) as ex:
        fut = {ex.submit(scan_target, t, opts): t for t in pending}
        for f in as_completed(fut):
            t = fut[f]
            try:
                results[t] = f.result()
                print(f"[OK] {t}")
            except Exception as e:
                print(f"[ERR] {t}: {e}")
            save_state()

    all_findings = merge_findings([fd for tr in results.values() for fd in tr.findings])
    json_payload = {
        "meta": meta,
        "results": {t: {
            "target": r.target,
            "alive": r.alive,
            "hostnames": r.hostnames,
            "open_ports": r.open_ports,
            "tool_runs": [asdict(x) for x in r.tool_runs],
            "findings": [{**asdict(f), "sources": sorted(f.sources), "cves": sorted(f.cves), "ports": sorted(f.ports), "protocols": sorted(f.protocols), "urls": sorted(f.urls)} for f in r.findings],
        } for t, r in results.items()},
        "findings": [{**asdict(f), "sources": sorted(f.sources), "cves": sorted(f.cves), "ports": sorted(f.ports), "protocols": sorted(f.protocols), "urls": sorted(f.urls)} for f in all_findings],
        "missing_optional_tools": missing_optional,
    }
    (run_dir / "results.json").write_text(json.dumps(json_payload, indent=2), encoding="utf-8")

    with (run_dir / "findings.csv").open("w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp)
        w.writerow(["target", "severity", "title", "sources", "ports", "urls", "cves", "description"])
        for f in all_findings:
            w.writerow([f.target, f.severity, f.title, ";".join(sorted(f.sources)), ";".join(map(str, sorted(f.ports))), ";".join(sorted(f.urls)), ";".join(sorted(f.cves)), f.description])

    report = run_dir / "report.html"
    render_report(report, meta, results, all_findings, missing_optional)
    print(f"Done:\n- {run_dir / 'state.json'}\n- {run_dir / 'results.json'}\n- {run_dir / 'findings.csv'}\n- {report}")
    try:
        webbrowser.open(f"file://{report.resolve()}")
    except Exception:
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--self-check", action="store_true", help="Run render compatibility self-check and exit")
    args = parser.parse_args()
    if args.self_check:
        _self_check_render_compat()
    else:
        main()
