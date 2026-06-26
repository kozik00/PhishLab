from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

if TYPE_CHECKING:
    from phishlab.models.analysis import AnalysisResult
    from phishlab.models.email import NormalizedEmail
    from phishlab.models.finding import Finding
    from phishlab.models.training import TrainingSample

console = Console(force_terminal=True)

RISK_COLORS = {
    "low": "green",
    "medium": "yellow",
    "high": "dark_orange",
    "critical": "red bold",
}

SEVERITY_COLORS = {
    "critical": "red bold",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "green",
    "info": "blue",
}


def print_email_info(email: NormalizedEmail, detailed: bool = False):
    lines = [
        f"[bold]Subject:[/] {email.subject or '—'}",
        f"[bold]From:[/] {email.from_display_name} <{email.from_address}>",
        f"[bold]To:[/] {', '.join(email.to) if email.to else '—'}",
        f"[bold]Date:[/] {email.date_raw or '—'}",
    ]

    if email.reply_to:
        lines.append(f"[bold]Reply-To:[/] {email.reply_to}")
    if email.return_path:
        lines.append(f"[bold]Return-Path:[/] {email.return_path}")
    if email.message_id:
        lines.append(f"[bold]Message-ID:[/] {email.message_id}")

    lines.append(f"[bold]Links:[/] {len(email.links)}")
    lines.append(f"[bold]Attachments:[/] {len(email.attachments)}")

    if email.authentication_results:
        lines.append(f"[bold]Auth:[/] {email.authentication_results}")

    console.print(Panel("\n".join(lines), title="Email", border_style="cyan"))

    if detailed and email.links:
        table = Table(title="Links")
        table.add_column("Text", max_width=25)
        table.add_column("Domain")
        table.add_column("Flags")
        for link in email.links:
            flags = []
            if link.is_ip_based:
                flags.append("[red]IP[/]")
            if link.is_shortened:
                flags.append("[yellow]Short[/]")
            if not link.uses_https:
                flags.append("[yellow]HTTP[/]")
            if link.is_punycode:
                flags.append("[red]Punycode[/]")
            table.add_row(
                (link.visible_text or "—")[:25],
                link.domain,
                " ".join(flags) if flags else "—",
            )
        console.print(table)

    if detailed and email.attachments:
        table = Table(title="Attachments")
        table.add_column("Filename")
        table.add_column("Extension")
        table.add_column("Size")
        table.add_column("Flags")
        for att in email.attachments:
            flags = []
            if att.has_double_extension:
                flags.append("[red]Double ext[/]")
            if att.is_suspicious_type:
                flags.append("[red]Suspicious[/]")
            table.add_row(
                att.filename,
                att.extension,
                f"{att.size_bytes / 1024:.1f} KB",
                " ".join(flags) if flags else "—",
            )
        console.print(table)


def print_analysis_summary(result: AnalysisResult):
    risk_color = RISK_COLORS.get(result.risk_level.value, "white")

    score_text = Text()
    score_text.append(f"{result.risk_score}", style=f"{risk_color}")
    score_text.append(f" / 100  ", style="dim")
    score_text.append(f"{result.risk_level.value.upper()}", style=f"{risk_color}")

    bar_width = 40
    filled = int(result.risk_score / 100 * bar_width)
    bar = f"[{risk_color}]{'#' * filled}[/][dim]{'.' * (bar_width - filled)}[/]"

    lines = [
        f"[bold]Risk Score:[/] {score_text}",
        bar,
        f"[bold]Findings:[/] {len(result.findings)}",
    ]

    if result.top_contributors:
        lines.append(f"[bold]Top Issues:[/] {', '.join(result.top_contributors[:3])}")

    console.print(Panel("\n".join(lines), title="Analysis Result", border_style=risk_color))


def print_findings_table(findings: list[Finding], verbose: bool = False):
    if not findings:
        console.print("[dim]No findings detected.[/]")
        return

    table = Table(title=f"Findings ({len(findings)})")
    table.add_column("#", justify="right", style="dim", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Title", max_width=35)
    table.add_column("Category", max_width=18)

    if verbose:
        table.add_column("Description", max_width=40)
        table.add_column("Evidence", max_width=25, style="dim")

    for i, f in enumerate(findings, 1):
        sev_color = SEVERITY_COLORS.get(f.severity.value, "white")
        row = [
            str(i),
            f"[{sev_color}]{f.severity.value.upper()}[/]",
            f.title,
            f.category.value.replace("_", " "),
        ]
        if verbose:
            row.append(f.description[:80])
            row.append((f.evidence or "—")[:40])
        table.add_row(*row)

    console.print(table)


def print_training_list(samples: list[TrainingSample]):
    table = Table(title="Training Samples")
    table.add_column("ID", style="cyan")
    table.add_column("Title")
    table.add_column("Difficulty")
    table.add_column("Tags", style="dim")

    diff_colors = {
        "beginner": "green",
        "intermediate": "yellow",
        "advanced": "red",
    }

    for s in samples:
        color = diff_colors.get(s.difficulty, "white")
        table.add_row(
            s.id,
            s.title,
            f"[{color}]{s.difficulty}[/]",
            ", ".join(s.tags),
        )

    console.print(table)


def print_quiz_result(score: dict):
    pct = score["score_percent"]
    if pct >= 80:
        color = "green"
        verdict = "Excellent!"
    elif pct >= 60:
        color = "yellow"
        verdict = "Good, but room to improve."
    else:
        color = "red"
        verdict = "Keep practicing!"

    lines = [
        f"[bold {color}]{pct:.0f}%[/]",
        f"{score['correct']} / {score['total']} correct",
        f"[{color}]{verdict}[/]",
    ]

    console.print(Panel("\n".join(lines), title="Quiz Score", border_style=color))
