import asyncio
import typer
import json
import sys
from typing import List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

from app.core.orchestrator import orchestrator
from app.report.generator import ReportGenerator
from app.core.config import settings

app = typer.Typer(name="security-testing", help="Security Testing Framework CLI")
console = Console()

@app.command("scan")
def start_scan(
    target_url: str = typer.Argument(..., help="Target URL to scan"),
    scanners: Optional[List[str]] = typer.Option(
        ["zap", "nuclei", "nikto"], 
        "--scanner", "-s", 
        help="Scanners to use (zap, nuclei, nikto)"
    ),
    output: Optional[str] = typer.Option(
        None, 
        "--output", "-o", 
        help="Output format (json, html, pdf)"
    ),
    wait: bool = typer.Option(
        False, 
        "--wait", "-w", 
        help="Wait for scan completion"
    )
):
    """Start a new security scan"""
    try:
        console.print(f"[bold blue]Starting security scan for:[/bold blue] {target_url}")
        console.print(f"[blue]Scanners:[/blue] {', '.join(scanners)}")
        
        # Start scan
        scan_id = asyncio.run(orchestrator.start_scan(target_url, scanners))
        
        console.print(f"[green]✓ Scan started successfully[/green]")
        console.print(f"[yellow]Scan ID:[/yellow] {scan_id}")
        
        if wait:
            console.print("[blue]Waiting for scan completion...[/blue]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Scanning...", total=100)
                
                while True:
                    scan_info = orchestrator.get_scan_status(scan_id)
                    if not scan_info:
                        break
                    
                    progress.update(task, completed=scan_info.get('progress', 0))
                    
                    if scan_info['status'] == 'completed':
                        progress.update(task, completed=100)
                        console.print("[green]✓ Scan completed successfully![/green]")
                        break
                    elif scan_info['status'] == 'failed':
                        console.print("[red]✗ Scan failed[/red]")
                        if scan_info.get('errors'):
                            for error in scan_info['errors']:
                                console.print(f"[red]Error:[/red] {error}")
                        break
                    
                    await asyncio.sleep(5)
            
            # Generate report if requested
            if output and scan_info['status'] == 'completed':
                console.print(f"[blue]Generating {output.upper()} report...[/blue]")
                generator = ReportGenerator()
                
                if output == 'json':
                    report_path = await generator.generate_json_report(scan_id, scan_info)
                elif output == 'html':
                    report_path = await generator.generate_html_report(scan_id, scan_info)
                elif output == 'pdf':
                    report_path = await generator.generate_pdf_report(scan_id, scan_info)
                else:
                    console.print(f"[red]Unsupported output format: {output}[/red]")
                    return
                
                console.print(f"[green]✓ Report generated:[/green] {report_path}")
        
        else:
            console.print("[yellow]Use 'security-testing status <scan_id>' to check progress[/yellow]")
    
    except Exception as e:
        console.print(f"[red]✗ Failed to start scan: {e}[/red]")
        sys.exit(1)

@app.command("status")
def get_scan_status(scan_id: str = typer.Argument(..., help="Scan ID to check")):
    """Get status of a specific scan"""
    try:
        scan_info = orchestrator.get_scan_status(scan_id)
        
        if not scan_info:
            console.print(f"[red]✗ Scan not found: {scan_id}[/red]")
            sys.exit(1)
        
        # Create status table
        table = Table(title=f"Scan Status: {scan_id}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Target URL", scan_info.get('target_url', 'N/A'))
        table.add_row("Status", _get_status_text(scan_info.get('status', 'unknown')))
        table.add_row("Progress", f"{scan_info.get('progress', 0)}%")
        table.add_row("Created", scan_info.get('created_at', 'N/A'))
        table.add_row("Updated", scan_info.get('updated_at', 'N/A'))
        table.add_row("Scan Types", ', '.join(scan_info.get('scan_types', [])))
        
        console.print(table)
        
        # Show errors if any
        if scan_info.get('errors'):
            console.print("\\n[red]Errors:[/red]")
            for error in scan_info['errors']:
                console.print(f"  • {error}")
        
        # Show results summary if completed
        if scan_info['status'] == 'completed' and scan_info.get('results'):
            console.print("\\n[green]Scan Results Summary:[/green]")
            _show_results_summary(scan_info['results'])
    
    except Exception as e:
        console.print(f"[red]✗ Failed to get scan status: {e}[/red]")
        sys.exit(1)

@app.command("list")
def list_scans(
    limit: int = typer.Option(10, "--limit", "-l", help="Number of scans to show"),
    status: Optional[str] = typer.Option(None, "--status", help="Filter by status")
):
    """List all scans"""
    try:
        all_scans = orchestrator.get_all_scans()
        
        # Filter by status if specified
        if status:
            all_scans = [s for s in all_scans if s.get('status') == status]
        
        # Sort by created_at descending
        sorted_scans = sorted(
            all_scans,
            key=lambda x: x.get('created_at', ''),
            reverse=True
        )[:limit]
        
        if not sorted_scans:
            console.print("[yellow]No scans found[/yellow]")
            return
        
        # Create scans table
        table = Table(title="Security Scans")
        table.add_column("Scan ID", style="cyan")
        table.add_column("Target URL", style="white")
        table.add_column("Status", style="white")
        table.add_column("Progress", style="white")
        table.add_column("Created", style="dim")
        
        for scan in sorted_scans:
            table.add_row(
                scan['id'][:8] + "...",
                scan.get('target_url', 'N/A')[:50],
                _get_status_text(scan.get('status', 'unknown')),
                f"{scan.get('progress', 0)}%",
                scan.get('created_at', 'N/A')[:19]
            )
        
        console.print(table)
        console.print(f"\\n[dim]Showing {len(sorted_scans)} of {len(all_scans)} total scans[/dim]")
    
    except Exception as e:
        console.print(f"[red]✗ Failed to list scans: {e}[/red]")
        sys.exit(1)

@app.command("report")
def generate_report(
    scan_id: str = typer.Argument(..., help="Scan ID to generate report for"),
    format: str = typer.Option("html", "--format", "-f", help="Report format (html, pdf, json)"),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path")
):
    """Generate report for a completed scan"""
    try:
        scan_info = orchestrator.get_scan_status(scan_id)
        
        if not scan_info:
            console.print(f"[red]✗ Scan not found: {scan_id}[/red]")
            sys.exit(1)
        
        if scan_info['status'] != 'completed':
            console.print(f"[red]✗ Scan not completed yet. Status: {scan_info['status']}[/red]")
            sys.exit(1)
        
        console.print(f"[blue]Generating {format.upper()} report...[/blue]")
        
        generator = ReportGenerator()
        
        if format == 'json':
            report_path = asyncio.run(generator.generate_json_report(scan_id, scan_info))
        elif format == 'html':
            report_path = asyncio.run(generator.generate_html_report(scan_id, scan_info))
        elif format == 'pdf':
            report_path = asyncio.run(generator.generate_pdf_report(scan_id, scan_info))
        else:
            console.print(f"[red]✗ Unsupported format: {format}[/red]")
            sys.exit(1)
        
        # Copy to custom output file if specified
        if output_file:
            import shutil
            shutil.copy2(report_path, output_file)
            console.print(f"[green]✓ Report generated:[/green] {output_file}")
        else:
            console.print(f"[green]✓ Report generated:[/green] {report_path}")
    
    except Exception as e:
        console.print(f"[red]✗ Failed to generate report: {e}[/red]")
        sys.exit(1)

@app.command("delete")
def delete_scan(scan_id: str = typer.Argument(..., help="Scan ID to delete")):
    """Delete a scan and its reports"""
    try:
        success = orchestrator.delete_scan(scan_id)
        
        if not success:
            console.print(f"[red]✗ Scan not found: {scan_id}[/red]")
            sys.exit(1)
        
        # Also delete reports
        generator = ReportGenerator()
        for format in ['html', 'pdf', 'json']:
            generator.delete_report(scan_id, format)
        
        console.print(f"[green]✓ Scan deleted successfully: {scan_id}[/green]")
    
    except Exception as e:
        console.print(f"[red]✗ Failed to delete scan: {e}[/red]")
        sys.exit(1)

@app.command("info")
def show_info():
    """Show framework information"""
    try:
        panel_content = f"""
[bold cyan]Security Testing Framework[/bold cyan]
Version: 1.0.0
Author: Security Team

[bold yellow]Configuration:[/bold yellow]
• API Host: {settings.API_HOST}:{settings.API_PORT}
• ZAP Host: {settings.ZAP_HOST}:{settings.ZAP_PORT}
• Reports Directory: {settings.REPORT_OUTPUT_DIR}
• Max Concurrent Scans: {settings.MAX_CONCURRENT_SCANS}

[bold green]Available Scanners:[/bold green]
• OWASP ZAP - Web Application Security Scanner
• Nuclei - Vulnerability Scanner
• Nikto - Web Server Scanner

[bold blue]OWASP Categories Covered:[/bold blue]
• {len(settings.OWASP_CATEGORIES)} categories from OWASP Top 10 2021
        """
        
        console.print(Panel(panel_content, title="Framework Information", border_style="blue"))
        
        # Show active scans
        active_scans = len([s for s in orchestrator.get_all_scans() if s['status'] == 'running'])
        console.print(f"\\n[yellow]Active Scans:[/yellow] {active_scans}")
        
        # Show report stats
        generator = ReportGenerator()
        stats = generator.get_report_stats()
        console.print(f"[yellow]Total Reports:[/yellow] {stats['total_reports']}")
    
    except Exception as e:
        console.print(f"[red]✗ Failed to show info: {e}[/red]")

def _get_status_text(status: str) -> Text:
    """Get colored status text"""
    status_colors = {
        'pending': 'yellow',
        'running': 'blue',
        'completed': 'green',
        'failed': 'red'
    }
    
    color = status_colors.get(status, 'white')
    return Text(status.title(), style=color)

def _show_results_summary(results: dict):
    """Show summary of scan results"""
    for scanner_name, scanner_results in results.items():
        if isinstance(scanner_results, dict) and 'summary' in scanner_results:
            summary = scanner_results['summary']
            total = summary.get('total', 0)
            high = summary.get('high', 0)
            medium = summary.get('medium', 0)
            
            console.print(f"  [cyan]{scanner_name.upper()}:[/cyan] {total} findings ({high} high, {medium} medium)")

if __name__ == "__main__":
    app()