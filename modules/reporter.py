import json
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

BANNER = """
[bold red] ██████╗███████╗██████╗ ██████╗ ███████╗██████╗ ██╗   ██╗███████╗[/bold red]
[bold red]██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝[/bold red]
[bold yellow]██║     █████╗  ██████╔╝██████╔╝█████╗  ██████╔╝██║   ██║███████╗[/bold yellow]
[bold yellow]██║     ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██╗██║   ██║╚════██║[/bold yellow]
[bold cyan]╚██████╗███████╗██║  ██║██████╔╝███████╗██║  ██║╚██████╔╝███████║[/bold cyan]
[bold cyan] ╚═════╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝[/bold cyan]
    [bold white]:: THE 3-HEADED HYBRID SECURITY AUDITOR (SAST + DAST + SCA) ::[/bold white]
         [dim]Authored by Boymirza R. | Autonomous Cyber Defense[/dim]
"""

class Reporter:
    @staticmethod
    def print_banner():
        console.print(BANNER)

    @staticmethod
    def print_terminal_report(results):
        console.print("\n")
        
        # Summary Counts
        sast_findings = results.get("sast", {}).get("findings", [])
        dast_findings = results.get("dast", {}).get("findings", [])
        sca_findings = results.get("sca", {}).get("findings", [])
        all_findings = sast_findings + dast_findings + sca_findings

        crit = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in all_findings if f.get("severity") == "HIGH")
        med = sum(1 for f in all_findings if f.get("severity") == "MEDIUM")
        low = sum(1 for f in all_findings if f.get("severity") in ["LOW", "INFO"])

        summary_text = f"[bold red]CRITICAL: {crit}[/bold red]  |  [bold yellow]HIGH: {high}[/bold yellow]  |  [bold cyan]MEDIUM: {med}[/bold cyan]  |  [bold green]LOW/INFO: {low}[/bold green]"
        console.print(Panel(summary_text, title="[bold white]AUDIT EXECUTIVE SUMMARY[/bold white]", border_style="red" if crit > 0 else "yellow"))

        # 1. SAST Table
        if sast_findings:
            table = Table(title="[bold cyan]HEAD 1: SAST FINDINGS (SOURCE CODE AUDIT)[/bold cyan]", border_style="cyan")
            table.add_column("Severity", justify="center")
            table.add_column("Rule / Vulnerability", style="bold")
            table.add_column("Location", style="dim")
            table.add_column("Snippet / Match", style="yellow")

            for f in sast_findings:
                sev_color = "red" if f["severity"] == "CRITICAL" else "yellow" if f["severity"] == "HIGH" else "cyan"
                table.add_row(
                    f"[{sev_color}]{f['severity']}[/{sev_color}]",
                    f"{f['rule_name']} ({f['rule_id']})",
                    f"{f['file']}:{f['line']}",
                    f['matched_line'][:45] + "..." if len(f['matched_line']) > 45 else f['matched_line']
                )
            console.print(table)
            console.print("\n")

        # 2. DAST Table
        if dast_findings:
            table = Table(title="[bold yellow]HEAD 2: DAST FINDINGS (WEB RECON & ATTACK SURFACE)[/bold yellow]", border_style="yellow")
            table.add_column("Severity", justify="center")
            table.add_column("Vulnerability / Finding", style="bold")
            table.add_column("Category", style="dim")
            table.add_column("Remediation", style="green")

            for f in dast_findings:
                sev_color = "red" if f["severity"] == "CRITICAL" else "yellow" if f["severity"] == "HIGH" else "cyan"
                table.add_row(
                    f"[{sev_color}]{f['severity']}[/{sev_color}]",
                    f['name'],
                    f.get('type', 'Web Finding'),
                    f['remediation'][:50] + "..." if len(f['remediation']) > 50 else f['remediation']
                )
            console.print(table)
            console.print("\n")

        # 3. SCA Table
        if sca_findings:
            table = Table(title="[bold magenta]HEAD 3: SCA FINDINGS (SUPPLY CHAIN & DEPENDENCY CVEs)[/bold magenta]", border_style="magenta")
            table.add_column("Severity", justify="center")
            table.add_column("Package", style="bold")
            table.add_column("Version", style="dim")
            table.add_column("CVE Identifier", style="red bold")
            table.add_column("Recommended Action", style="green")

            for f in sca_findings:
                sev_color = "red" if f["severity"] == "CRITICAL" else "yellow" if f["severity"] == "HIGH" else "cyan"
                table.add_row(
                    f"[{sev_color}]{f['severity']}[/{sev_color}]",
                    f['package'],
                    f['installed_version'],
                    f['cve'],
                    f['remediation']
                )
            console.print(table)
            console.print("\n")

    @staticmethod
    def generate_html_report(results, output_path="cerberus_report.html"):
        sast = results.get("sast", {}).get("findings", [])
        dast = results.get("dast", {}).get("findings", [])
        sca = results.get("sca", {}).get("findings", [])
        all_f = sast + dast + sca

        crit = sum(1 for f in all_f if f.get("severity") == "CRITICAL")
        high = sum(1 for f in all_f if f.get("severity") == "HIGH")
        med = sum(1 for f in all_f if f.get("severity") == "MEDIUM")
        low = sum(1 for f in all_f if f.get("severity") in ["LOW", "INFO"])

        def render_rows(findings_list, is_sast=False, is_sca=False):
            html = ""
            for f in findings_list:
                sev = f.get("severity", "LOW")
                badge_class = "sev-crit" if sev == "CRITICAL" else "sev-high" if sev == "HIGH" else "sev-med" if sev == "MEDIUM" else "sev-low"
                
                title = f.get("rule_name") or f.get("name") or f.get("cve", "Vulnerability")
                desc = f.get("description", "")
                rem = f.get("remediation", "")
                extra = f"{f.get('file', '')}:{f.get('line', '')}" if is_sast else f"{f.get('package', '')} ({f.get('installed_version', '')})" if is_sca else f.get("type", "")

                html += f"""
                <tr>
                    <td><span class="badge {badge_class}">{sev}</span></td>
                    <td><strong>{title}</strong><br><small style="color:#64748b;">{desc}</small></td>
                    <td><code>{extra}</code></td>
                    <td style="color:#10b981;">{rem}</td>
                </tr>
                """
            return html or "<tr><td colspan='4' style='text-align:center;color:#64748b;'>No vulnerabilities detected in this category.</td></tr>"

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CERBERUS // Security Audit Report</title>
    <style>
        body {{
            background: #090d16;
            color: #f1f5f9;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            padding: 40px 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            border-bottom: 1px solid rgba(255,255,255,0.08);
            padding-bottom: 24px;
            margin-bottom: 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        h1 {{
            margin: 0;
            font-size: 28px;
            letter-spacing: 1px;
            color: #00f0ff;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 36px;
        }}
        .stat-card {{
            background: rgba(18, 24, 38, 0.6);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .stat-val {{
            font-size: 32px;
            font-weight: 800;
            margin-top: 6px;
        }}
        .val-crit {{ color: #ef4444; }}
        .val-high {{ color: #f59e0b; }}
        .val-med {{ color: #00f0ff; }}
        .val-low {{ color: #10b981; }}
        
        .section-title {{
            font-size: 18px;
            font-weight: 700;
            margin: 32px 0 16px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: rgba(18, 24, 38, 0.4);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 30px;
        }}
        th, td {{
            padding: 14px 18px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            font-size: 14px;
        }}
        th {{
            background: rgba(255,255,255,0.03);
            color: #94a3b8;
            font-size: 12px;
            text-transform: uppercase;
        }}
        .badge {{
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
        }}
        .sev-crit {{ background: rgba(239,68,68,0.2); color: #ef4444; border: 1px solid #ef4444; }}
        .sev-high {{ background: rgba(245,158,11,0.2); color: #f59e0b; border: 1px solid #f59e0b; }}
        .sev-med {{ background: rgba(0,240,255,0.2); color: #00f0ff; border: 1px solid #00f0ff; }}
        .sev-low {{ background: rgba(16,185,129,0.2); color: #10b981; border: 1px solid #10b981; }}
        code {{
            background: rgba(0,0,0,0.4);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            color: #e2e8f0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>CERBERUS // AUDIT REPORT</h1>
                <div style="color: #64748b; font-size: 13px; margin-top: 4px;">
                    Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Hybrid Security Engine
                </div>
            </div>
            <div style="font-family: monospace; color: #00f0ff;">
                STATUS: AUDIT_COMPLETE
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div style="color: #64748b; font-size: 12px;">CRITICAL SEVERITY</div>
                <div class="stat-val val-crit">{crit}</div>
            </div>
            <div class="stat-card">
                <div style="color: #64748b; font-size: 12px;">HIGH SEVERITY</div>
                <div class="stat-val val-high">{high}</div>
            </div>
            <div class="stat-card">
                <div style="color: #64748b; font-size: 12px;">MEDIUM SEVERITY</div>
                <div class="stat-val val-med">{med}</div>
            </div>
            <div class="stat-card">
                <div style="color: #64748b; font-size: 12px;">LOW / INFO</div>
                <div class="stat-val val-low">{low}</div>
            </div>
        </div>

        <div class="section-title" style="color: #00f0ff;">
            HEAD 1: SOURCE CODE AUDIT (SAST)
        </div>
        <table>
            <thead>
                <tr>
                    <th style="width: 100px;">Severity</th>
                    <th>Vulnerability & Description</th>
                    <th>File & Line</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {render_rows(sast, is_sast=True)}
            </tbody>
        </table>

        <div class="section-title" style="color: #f59e0b;">
            HEAD 2: WEB RECON & ATTACK SURFACE (DAST)
        </div>
        <table>
            <thead>
                <tr>
                    <th style="width: 100px;">Severity</th>
                    <th>Vulnerability & Description</th>
                    <th>Finding Type</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {render_rows(dast)}
            </tbody>
        </table>

        <div class="section-title" style="color: #a855f7;">
            HEAD 3: SUPPLY CHAIN & DEPENDENCY CVEs (SCA)
        </div>
        <table>
            <thead>
                <tr>
                    <th style="width: 100px;">Severity</th>
                    <th>Vulnerability & CVE</th>
                    <th>Package & Version</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {render_rows(sca, is_sca=True)}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_template)
        console.print(f"[bold green][✓] HTML Report saved successfully to:[/bold green] [cyan]{output_path}[/cyan]")
