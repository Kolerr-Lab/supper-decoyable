import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Literal

import typer
from rich.console import Console
from rich.table import Table

from .registry import get_scanners, BaseScanner, Finding
from ..scanners.secrets import SecretsScanner
from ..scanners.deps import DepsScanner

app = typer.Typer(help="Decoyable CLI")
console = Console()

# Ensure scanners are registered
_ = [SecretsScanner, DepsScanner]


def _serialize_finding(f: Finding) -> Dict[str, Any]:
    return {
        "scanner": getattr(f, "scanner", None),
        "severity": getattr(f, "severity", None),
        "message": getattr(f, "message", None),
        "path": str(getattr(f, "path", "") or ""),
        "line": getattr(f, "line", None),
    }


def _print_table(findings: List[Finding]) -> None:
    table = Table(title="Findings")
    table.add_column("Scanner", style="cyan")
    table.add_column("Severity", style="magenta")
    table.add_column("Message", style="white")
    table.add_column("Path", style="green")
    table.add_column("Line", justify="right")
    for f in findings:
        table.add_row(
            str(getattr(f, "scanner", "-") or "-"),
            str(getattr(f, "severity", "-") or "-"),
            str(getattr(f, "message", "-") or "-"),
            str(getattr(f, "path", "-") or "-"),
            str(getattr(f, "line", "-") or "-"),
        )
    console.print(table)

def get_app():
    return app

@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Target path to scan"),
    exclude: Optional[List[str]] = typer.Option(
        None,
        "--exclude",
        "-e",
        help="Paths or globs to exclude. Can be passed multiple times.",
    ),
    format: Literal["table", "json"] = typer.Option(
        "table", "--format", "-f", help="Output format"
    ),
) -> None:
    """Run all registered scanners against PATH."""
    target = path.resolve()
    exclude_list = [str(Path(p).resolve()) for p in (exclude or [])]

    findings: List[Finding] = []
    for scanner_cls in get_scanners():
        scanner: BaseScanner = scanner_cls()
        try:
            results = scanner.scan(str(target), exclude=exclude_list)
            if results:
                findings.extend(results)
        except Exception as exc:
            console.print(f"[red]Scanner {scanner_cls.__name__} failed:[/red] {exc}")

    if not findings:
        console.print("[green]No findings[/green]")
        return

    if format == "json":
        payload = [_serialize_finding(f) for f in findings]
        console.print_json(json.dumps(payload))
    else:
        _print_table(findings)
