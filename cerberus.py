#!/usr/bin/env python3
import sys
import json
import argparse
from pathlib import Path

# Add local directory to module search path
sys.path.insert(0, str(Path(__file__).parent))

from modules.sast import SASTScanner
from modules.dast import DASTScanner
from modules.sca import SCAScanner
from modules.reporter import Reporter, console

def parse_args():
    parser = argparse.ArgumentParser(
        description="CERBERUS: The 3-Headed Hybrid Security Auditor (SAST + DAST + SCA)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cerberus.py --code /path/to/project/
  python3 cerberus.py --url https://target.com/
  python3 cerberus.py --deps /path/to/project/
  python3 cerberus.py --code ./src --url http://127.0.0.1:8080 --html report.html
  python3 cerberus.py --all ./my-web-app --html audit_report.html
        """
    )

    parser.add_argument("--code", "-c", type=str, help="Target directory or file for SAST Source Code Audit (Head 1)")
    parser.add_argument("--url", "-u", type=str, help="Target URL for DAST Web Recon & Attack Surface Scan (Head 2)")
    parser.add_argument("--deps", "-d", type=str, help="Target directory for SCA Dependency & CVE Scan (Head 3)")
    parser.add_argument("--all", "-a", type=str, help="Run Full Triad (SAST + SCA on directory, DAST on target if URL provided)")
    parser.add_argument("--html", type=str, help="Generate interactive HTML report (e.g., --html report.html)")
    parser.add_argument("--json", type=str, help="Export scan results to JSON file (e.g., --json output.json)")
    parser.add_argument("--no-banner", action="store_true", help="Suppress Cerberus ASCII banner")

    return parser.parse_args()

def main():
    args = parse_args()

    if not args.no_banner:
        Reporter.print_banner()

    if not any([args.code, args.url, args.deps, args.all]):
        console.print("[bold red][!] Error: No audit target specified.[/bold red]")
        console.print("[dim]Use --help to view usage instructions, e.g., python3 cerberus.py --code ./src[/dim]\n")
        sys.exit(1)

    results = {
        "timestamp": None,
        "sast": {},
        "dast": {},
        "sca": {}
    }

    # Head 1: SAST
    sast_target = args.code or args.all
    if sast_target:
        console.print(f"[bold cyan][*] Activating HEAD 1: SAST Code Audit on '{sast_target}'...[/bold cyan]")
        sast_scanner = SASTScanner()
        results["sast"] = sast_scanner.scan(sast_target)
        count = results["sast"].get("findings_count", 0)
        console.print(f"[green][✓] Head 1 scan complete: {count} security issues identified.[/green]")

    # Head 2: DAST
    if args.url:
        console.print(f"[bold yellow][*] Activating HEAD 2: DAST Web Recon on '{args.url}'...[/bold yellow]")
        dast_scanner = DASTScanner()
        results["dast"] = dast_scanner.scan(args.url)
        count = results["dast"].get("findings_count", 0)
        console.print(f"[green][✓] Head 2 scan complete: {count} web perimeter issues identified.[/green]")

    # Head 3: SCA
    sca_target = args.deps or args.all
    if sca_target:
        console.print(f"[bold magenta][*] Activating HEAD 3: SCA Dependency CVE Audit on '{sca_target}'...[/bold magenta]")
        sca_scanner = SCAScanner()
        results["sca"] = sca_scanner.scan(sca_target)
        count = results["sca"].get("findings_count", 0)
        console.print(f"[green][✓] Head 3 scan complete: {count} vulnerable dependencies identified.[/green]")

    # Display Terminal Summary & Tables
    Reporter.print_terminal_report(results)

    # HTML Report
    if args.html:
        Reporter.generate_html_report(results, output_path=args.html)

    # JSON Export
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        console.print(f"[bold green][✓] Raw JSON output saved to:[/bold green] [cyan]{args.json}[/cyan]")

if __name__ == "__main__":
    main()
