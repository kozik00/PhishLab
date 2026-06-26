from __future__ import annotations

from pathlib import Path

import click

from phishlab_cli.output import (
    print_analysis_summary,
    print_email_info,
    print_findings_table,
    print_training_list,
    print_quiz_result,
)


@click.group()
@click.version_option(version="0.2.0", prog_name="PhishLab")
def cli():
    """PhishLab — Local-first Email Threat Analysis CLI."""


@cli.command()
@click.argument("eml_path", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON")
@click.option("--verbose", "-v", is_flag=True, help="Show all findings detail")
def analyze(eml_path: Path, as_json: bool, verbose: bool):
    """Analyze an .eml file for phishing indicators."""
    from phishlab.parser.eml_parser import parse_eml_file
    from phishlab.analyzers.orchestrator import run_analysis
    from phishlab.scoring.risk_score import build_analysis_result

    email = parse_eml_file(eml_path)
    findings = run_analysis(email)
    result = build_analysis_result(email, findings)

    if as_json:
        click.echo(result.model_dump_json(indent=2))
        return

    print_email_info(email)
    print_analysis_summary(result)
    print_findings_table(result.findings, verbose=verbose)


@cli.command()
@click.argument("eml_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--format", "-f",
    "fmt",
    type=click.Choice(["json", "markdown", "html", "user"]),
    default="markdown",
    help="Report format",
)
@click.option("--output", "-o", "out_path", type=click.Path(path_type=Path), help="Output file path")
def report(eml_path: Path, fmt: str, out_path: Path | None):
    """Generate a report for an .eml file."""
    from phishlab.parser.eml_parser import parse_eml_file
    from phishlab.analyzers.orchestrator import run_analysis
    from phishlab.scoring.risk_score import build_analysis_result
    from phishlab.reports.generator import (
        generate_json_report,
        generate_markdown_report,
        generate_html_report,
        generate_user_report,
    )

    email = parse_eml_file(eml_path)
    findings = run_analysis(email)
    result = build_analysis_result(email, findings)

    generators = {
        "json": generate_json_report,
        "markdown": generate_markdown_report,
        "html": generate_html_report,
        "user": generate_user_report,
    }

    content = generators[fmt](result, email)

    if out_path:
        out_path.write_text(content, encoding="utf-8")
        click.echo(f"Report saved to {out_path}")
    else:
        click.echo(content)


@cli.command()
@click.argument("eml_path", type=click.Path(exists=True, path_type=Path))
def inspect(eml_path: Path):
    """Show parsed email metadata without analysis."""
    from phishlab.parser.eml_parser import parse_eml_file

    email = parse_eml_file(eml_path)
    print_email_info(email, detailed=True)


@cli.command()
def training():
    """List available training samples."""
    from phishlab.training.library import load_training_samples

    samples = load_training_samples()
    print_training_list(samples)


@cli.command()
@click.argument("sample_id", required=False)
@click.option("--all", "run_all", is_flag=True, help="Quiz all samples")
def quiz(sample_id: str | None, run_all: bool):
    """Take a phishing identification quiz."""
    from phishlab.training.library import (
        get_sample_by_id,
        get_sample_eml_path,
        load_training_samples,
    )
    from phishlab.parser.eml_parser import parse_eml_file
    from phishlab.training.quiz import evaluate_answer, calculate_quiz_score

    if sample_id and not run_all:
        sample = get_sample_by_id(sample_id)
        if not sample:
            click.echo(f"Sample '{sample_id}' not found.", err=True)
            raise SystemExit(1)
        samples = [sample]
    else:
        samples = load_training_samples()

    results = []
    for sample in samples:
        eml_path = get_sample_eml_path(sample)
        email = parse_eml_file(eml_path)

        click.echo(f"\n{'=' * 60}")
        click.echo(f"  {sample.title}")
        click.echo(f"  Difficulty: {sample.difficulty}")
        click.echo(f"{'=' * 60}")
        click.echo(f"  From: {email.from_display_name} <{email.from_address}>")
        click.echo(f"  Subject: {email.subject}")
        if email.text_body:
            preview = email.text_body[:300].replace("\n", "\n  ")
            click.echo(f"  Body: {preview}{'...' if len(email.text_body) > 300 else ''}")
        click.echo()

        answer = click.confirm("  Is this email a phishing attempt?")
        result = evaluate_answer(sample.id, answer)
        results.append(result)

        if result.correct:
            click.secho("  Correct!", fg="green", bold=True)
        else:
            click.secho("  Incorrect.", fg="red", bold=True)
        click.echo(f"  {result.explanation}")

    if len(results) > 1:
        score = calculate_quiz_score(results)
        print_quiz_result(score)


@cli.command()
@click.argument("directory", type=click.Path(exists=True, path_type=Path))
@click.option("--threshold", "-t", type=int, default=50, help="Risk score threshold to flag")
def scan(directory: Path, threshold: int):
    """Scan a directory for .eml files and summarize risks."""
    from phishlab.parser.eml_parser import parse_eml_file
    from phishlab.analyzers.orchestrator import run_analysis
    from phishlab.scoring.risk_score import build_analysis_result

    from rich.console import Console
    from rich.table import Table

    eml_files = sorted(directory.glob("**/*.eml"))
    if not eml_files:
        click.echo("No .eml files found.")
        return

    console = Console()
    table = Table(title=f"Scan Results — {len(eml_files)} files")
    table.add_column("File", style="cyan", max_width=40)
    table.add_column("From", max_width=25)
    table.add_column("Subject", max_width=30)
    table.add_column("Score", justify="right")
    table.add_column("Risk", justify="center")
    table.add_column("Findings", justify="right")

    flagged = 0
    for path in eml_files:
        try:
            email = parse_eml_file(path)
            findings = run_analysis(email)
            result = build_analysis_result(email, findings)

            risk_style = {
                "low": "green",
                "medium": "yellow",
                "high": "dark_orange",
                "critical": "red bold",
            }.get(result.risk_level.value, "white")

            table.add_row(
                path.name,
                email.from_address[:25],
                (email.subject or "—")[:30],
                str(result.risk_score),
                f"[{risk_style}]{result.risk_level.value.upper()}[/]",
                str(len(result.findings)),
            )

            if result.risk_score >= threshold:
                flagged += 1
        except Exception as e:
            table.add_row(path.name, "—", "—", "—", "[red]ERROR[/]", str(e)[:20])

    console.print(table)
    console.print(f"\n[bold]{flagged}[/bold] of {len(eml_files)} files above threshold ({threshold})")


@cli.command()
@click.argument("eml_path", type=click.Path(exists=True, path_type=Path))
@click.option("--vt-key", envvar="VIRUSTOTAL_API_KEY", help="VirusTotal API key (or set VIRUSTOTAL_API_KEY)")
@click.option("--sb-key", envvar="GOOGLE_SAFE_BROWSING_KEY", help="Google Safe Browsing key (or set GOOGLE_SAFE_BROWSING_KEY)")
def enrich(eml_path: Path, vt_key: str | None, sb_key: str | None):
    """Enrich analysis with external threat intelligence (opt-in).

    Requires at least one API key. Only URLs and file hashes are sent externally.
    """
    from phishlab.parser.eml_parser import parse_eml_file
    from rich.console import Console
    from rich.table import Table

    console = Console(force_terminal=True)

    if not vt_key and not sb_key:
        click.echo("At least one API key is required.", err=True)
        click.echo("  --vt-key / VIRUSTOTAL_API_KEY for VirusTotal", err=True)
        click.echo("  --sb-key / GOOGLE_SAFE_BROWSING_KEY for Safe Browsing", err=True)
        raise SystemExit(1)

    email = parse_eml_file(eml_path)

    if vt_key:
        from phishlab.integrations.virustotal import VirusTotalClient

        vt = VirusTotalClient(vt_key)

        if email.links:
            table = Table(title="VirusTotal — URL Scan")
            table.add_column("Domain", style="cyan")
            table.add_column("Detections", justify="right")
            table.add_column("Status")

            unique_domains = list({l.domain for l in email.links if l.domain})
            for domain in unique_domains:
                result = vt.check_domain(domain)
                if not result.found:
                    table.add_row(domain, "—", "[dim]Not found[/]")
                elif result.is_malicious:
                    table.add_row(domain, result.detection_ratio, "[red bold]MALICIOUS[/]")
                elif result.is_suspicious:
                    table.add_row(domain, result.detection_ratio, "[yellow]Suspicious[/]")
                else:
                    table.add_row(domain, result.detection_ratio, "[green]Clean[/]")

            console.print(table)

        if email.attachments:
            table = Table(title="VirusTotal — File Hash Scan")
            table.add_column("Filename")
            table.add_column("SHA256", style="dim", max_width=20)
            table.add_column("Detections", justify="right")
            table.add_column("Status")

            for att in email.attachments:
                if att.sha256:
                    result = vt.check_hash(att.sha256)
                    if not result.found:
                        table.add_row(att.filename, att.sha256[:20], "—", "[dim]Not found[/]")
                    elif result.is_malicious:
                        table.add_row(att.filename, att.sha256[:20], result.detection_ratio, "[red bold]MALICIOUS[/]")
                    else:
                        table.add_row(att.filename, att.sha256[:20], result.detection_ratio, "[green]Clean[/]")

            console.print(table)

    if sb_key and email.links:
        from phishlab.integrations.url_reputation import SafeBrowsingClient

        sb = SafeBrowsingClient(sb_key)
        urls = [l.href for l in email.links if l.href]
        results = sb.check_urls(urls)

        table = Table(title="Google Safe Browsing")
        table.add_column("URL", max_width=50)
        table.add_column("Status")
        table.add_column("Threats")

        for r in results:
            if r.is_dangerous:
                table.add_row(r.url[:50], "[red bold]DANGEROUS[/]", ", ".join(r.threats))
            elif r.error:
                table.add_row(r.url[:50], "[yellow]Error[/]", r.error)
            else:
                table.add_row(r.url[:50], "[green]Safe[/]", "—")

        console.print(table)
