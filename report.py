from __future__ import annotations

import csv
import json

from rich.console import Console
from rich.table import Table

from analyzer.base import CtFinding

SEVERITY_COLOR = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}


def print_terminal(findings: list[CtFinding], source: str = "CloudTrail") -> None:
    console = Console()
    if not findings:
        console.print(f"[bold green]✓ No findings in {source}[/bold green]")
        return
    table = Table(title=f"aws-cloudtrail-analyzer — {source}", show_lines=True)
    table.add_column("Rule", style="bold")
    table.add_column("Severity")
    table.add_column("Event")
    table.add_column("Actor")
    table.add_column("Region")
    table.add_column("Title")
    for f in findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(f.rule_id, f"[{color}]{f.severity}[/{color}]",
                      f.event_name, f.actor, f.region, f.title)
    console.print(table)


def print_json(findings: list[CtFinding]) -> None:
    data = [{"rule_id": f.rule_id, "severity": f.severity, "event_name": f.event_name,
             "actor": f.actor, "region": f.region, "event_time": f.event_time,
             "title": f.title, "detail": f.detail, "remediation": f.remediation}
            for f in findings]
    print(json.dumps(data, indent=2))


def write_csv(findings: list[CtFinding], path: str) -> None:
    fieldnames = ["rule_id", "severity", "event_name", "actor", "region",
                  "event_time", "title", "detail", "remediation"]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            writer.writerow({"rule_id": f.rule_id, "severity": f.severity,
                             "event_name": f.event_name, "actor": f.actor,
                             "region": f.region, "event_time": f.event_time,
                             "title": f.title, "detail": f.detail,
                             "remediation": f.remediation})
