import socket
import json
import csv
import argparse
import concurrent.futures
from datetime import datetime
from dataclasses import dataclass, field, asdict

# importing data
from data.NISTControls import nistControls
from data.PortRisks import portRisks
from data.ScanProfiles import scanProfiles


# NIST 800-53 rev. 5
# Source:  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf

riskOrder = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

@dataclass
class PortFinding:
    port:        int
    service:     str
    state:       str
    risk:        str
    controls:    list[str]
    reason:      str
    remediation: str

@dataclass
class ScanResult:
    target:       str
    resolvedIp:  str
    scanProfile: str
    framework:    str
    timestamp:    str
    findings:     list[PortFinding] = field(default_factory=list)

    @property
    def open_ports(self):
        return [f for f in self.findings if f.state == "OPEN"]

    @property
    def risk_summary(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.open_ports:
            if f.risk in counts:
                counts[f.risk] += 1
        return counts

    @property
    def overall_risk(self) -> str:
        s = self.risk_summary
        if s["CRITICAL"] > 0:  return "CRITICAL"
        if s["HIGH"] > 0:      return "HIGH"
        if s["MEDIUM"] > 0:    return "MEDIUM"
        return "LOW"

    @property
    def violated_controls(self) -> list[str]:
        seen, out = set(), []
        for f in self.open_ports:
            for c in f.controls:
                if c not in seen:
                    seen.add(c)
                    out.append(c)
        return sorted(out)

class RiskAssessor:

    def __init__(self, target: str, profile: str = "standard",
                 timeout: float = 1.5, threads: int = 50):
        self.target  = target
        self.profile = profile
        self.timeout = timeout
        self.threads = threads

    def resolve_host(self) -> str:
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror as e:
            raise SystemExit(f"[ERROR] Cannot resolve '{self.target}': {e}")

    def check_port(self, ip: str, port: int) -> PortFinding:
        """Attempt TCP connect to a single port and return a PortFinding."""
        db  = portRisks.get(port, {})
        svc = db.get("service", f"port-{port}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((ip, port))
            state  = "OPEN" if result == 0 else "CLOSED"
        except OSError:
            state = "FILTERED"
        finally:
            sock.close()

        return PortFinding(
            port        = port,
            service     = svc,
            state       = state,
            risk        = db.get("risk", "UNKNOWN")        if state == "OPEN" else "N/A",
            controls    = db.get("controls", [])           if state == "OPEN" else [],
            reason      = db.get("reason", "Unknown port") if state == "OPEN" else "",
            remediation = db.get("remediation", "")        if state == "OPEN" else "",
        )

    def run(self) -> ScanResult:
        ports = scanProfiles.get(self.profile, scanProfiles["standard"])
        ip    = self.resolve_host()

        print(f"\n{'─'*60}")
        print(f"  IT Risk Assessor  |  NIST 800-53")
        print(f"{'─'*60}")
        print(f"  Target   : {self.target} ({ip})")
        print(f"  Profile  : {self.profile} ({len(ports)} ports)")
        print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'-'*60}\n")

        result = ScanResult(
            target       = self.target,
            resolvedIp  = ip,
            scanProfile = self.profile,
            framework    = "NIST 800-53",
            timestamp    = datetime.now().isoformat(),
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self.check_port, ip, p): p for p in ports}
            done = 0
            for future in concurrent.futures.as_completed(futures):
                finding = future.result()
                result.findings.append(finding)
                done += 1
                pct  = int((done / len(ports)) * 30)
                bar = f'{"="*pct + " "*(30-pct)}'
                icon = {"OPEN": "●", "CLOSED": "○", "FILTERED": "◌"}.get(finding.state, "?")
                risk_tag = f" [{finding.risk}]" if finding.state == "OPEN" else ""
                print(f"\r  [{bar}] {done}/{len(ports)}  {icon} {finding.port:>5}/{finding.service:<12}{risk_tag}        ",
                      end="", flush=True)

        print("\n")
        result.findings.sort(
            key=lambda f: (riskOrder.get(f.risk, 0) if f.state == "OPEN" else -1),
            reverse=True,
        )
        return result



def _risk_colour(risk: str) -> str:
    """ANSI colour codes for terminal output."""
    return {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[93m",
        "MEDIUM":   "\033[94m",
        "LOW":      "\033[92m",
    }.get(risk, "\033[0m")

RESET = "\033[0m"
BOLD  = "\033[1m"


def print_report(result: ScanResult):
    open_ports = result.open_ports
    summary    = result.risk_summary

    print(f"{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  ASSESSMENT REPORT{RESET}")
    print(f"{'='*60}")
    print(f"  Target     : {result.target} ({result.resolvedIp})")
    print(f"  Framework  : {result.framework}")
    print(f"  Scan time  : {result.timestamp[:19]}")
    print(f"  Open ports : {len(open_ports)}")
    print(f"  Overall    : {_risk_colour(result.overall_risk)}{BOLD}{result.overall_risk}{RESET}")
    print(f"\n  Risk Breakdown")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = summary[level]
        bar   = "▮" * count
        print(f"    {_risk_colour(level)}{level:<10}{RESET} {bar} {count}")

    if open_ports:
        print(f"\n{BOLD}  FINDINGS{RESET}")
        print(f"  {'PORT':<6} {'SERVICE':<14} {'RISK':<10} {'CONTROLS'}")
        print(f"  {'-'*56}")
        for f in open_ports:
            ctrls = ", ".join(f.controls) if f.controls else "-"
            colour = _risk_colour(f.risk)
            print(f"  {f.port:<6} {f.service:<14} {colour}{f.risk:<10}{RESET} {ctrls}")
            print(f"         {BOLD}->{RESET} {f.reason}")
            print(f"           Fix: {f.remediation}\n")

    if result.violated_controls:
        print(f"{BOLD}  CONTROL VIOLATIONS  ({result.framework}){RESET}")
        print(f"  {'-'*56}")
        for cid in result.violated_controls:
            ctrl = nistControls.get(cid, {})
            print(f"  {BOLD}{cid}{RESET}  {ctrl.get('name','')}")
            print(f"       {ctrl.get('description','')}\n")

    print(f"{'═'*60}\n")


def export_json(result: ScanResult, path: str):
    data = asdict(result)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[{BOLD}JSON report saved -> {path}")


def export_csv(result: ScanResult, path: str):
    rows = []
    for f in result.open_ports:
        rows.append({
            "Target":      result.target,
            "IP":          result.resolvedIp,
            "Port":        f.port,
            "Service":     f.service,
            "Risk":        f.risk,
            "Controls":    ", ".join(f.controls),
            "Reason":      f.reason,
            "Remediation": f.remediation,
            "Timestamp":   result.timestamp,
        })
    if not rows:
        print("[!] No open ports found - CSV not written.")
        return
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"{BOLD} CSV report saved  -> {path}")


def export_risk_register(result: ScanResult, path: str):
    """Export a GRC-style risk register CSV (as used in IT Risk tools)."""
    rows = []
    for i, f in enumerate(result.open_ports, 1):
        risk_score = {"CRITICAL": 20, "HIGH": 15, "MEDIUM": 8, "LOW": 3}.get(f.risk, 0)
        rows.append({
            "Risk ID":     f"RSK-{i:03d}",
            "Description": f"{f.service} (port {f.port}) exposed --- {f.reason}",
            "Asset":       result.target,
            "Likelihood":  "High" if f.risk in ("CRITICAL","HIGH") else "Medium",
            "Impact":      f.risk.capitalize(),
            "Risk Score":  risk_score,
            "Controls":    ", ".join(f.controls) if f.controls else "N/A",
            "Framework":   result.framework,
            "Remediation": f.remediation,
            "Owner":       "Network / Security Team",
            "Status":      "Open",
            "Due Date":    "",
        })
    if not rows:
        print("[!] No open ports - risk register not written.")
        return
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"{BOLD} Risk register saved -> {path}")



def parse_args():
    p = argparse.ArgumentParser(
        description="IT Risk Assessor - port scanner with NIST 800-53 control mapping",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py --target scanme.nmap.org
  python scanner.py --target 192.168.1.1 --profile full
  python scanner.py --target scanme.nmap.org --output json
  python scanner.py --target scanme.nmap.org --output csv --outfile results.csv
        """,
    )
    p.add_argument("--target",  required=True,  help="Hostname or IP to assess")
    p.add_argument("--profile", default="standard",
                   choices=["quick", "standard", "full"],
                   help="Scan profile (default: standard)")
    p.add_argument("--output",  default="terminal",
                   choices=["terminal", "json", "csv", "all"],
                   help="Output format (default: terminal)")
    p.add_argument("--outfile", default="",
                   help="Output filename (auto-named if omitted)")
    p.add_argument("--timeout", type=float, default=1.5,
                   help="Socket timeout in seconds (default: 1.5)")
    p.add_argument("--threads", type=int,   default=50,
                   help="Concurrent scan threads (default: 50)")
    return p.parse_args()


def main():
    args    = parse_args()
    assessor = RiskAssessor(args.target, args.profile, args.timeout, args.threads)
    result   = assessor.run()

    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = args.outfile or f"risk_report_{args.target.replace('.','_')}_{ts}"

    # A lot of times, cybersecurity pros like Terminal interfaces. For example, some people prefer Tshark over the widely used
    # Wireshark.

    if args.output in ("terminal", "all"):
        print_report(result)

    # json is important because other tools, such as splunk / Elasticsearch ingest events as json.
    # creating json outputs is good because it can be fed into those (and other) pipelines.
    if args.output in ("json", "all"):
        export_json(result, base + ".json" if not args.outfile.endswith(".json") else args.outfile)

    if args.output in ("csv", "all"):
        export_csv(result,           base + "_findings.csv")
        export_risk_register(result, base + "_risk_register.csv")


if __name__ == "__main__":
    main()