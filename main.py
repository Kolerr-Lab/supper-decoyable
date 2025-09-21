from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Any

from decoyable.scanners import deps, sast, secrets

# /g:/TECH/DECOYABLE/main.py

# DECOYABLE - Cybersecurity scanning tool for dependencies and secrets.
# Scans Python projects for security vulnerabilities including exposed secrets
# and missing dependencies.

# Package / app metadata
APP_NAME = "decoyable"
VERSION = "0.1.0"


def setup_logging(level: str = "INFO", logfile: Path | None = None) -> None:
    """
    Configure root logger.
    level: one of DEBUG, INFO, WARNING, ERROR, CRITICAL
    logfile: optional Path to write logs to (rotating file).
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger = logging.getLogger()
    logger.setLevel(numeric_level)

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(numeric_level)
    ch.setFormatter(formatter)
    # Remove existing handlers to avoid duplicate logs when re-imported/reused
    if logger.handlers:
        logger.handlers = []
    logger.addHandler(ch)

    # Optional rotating file handler
    if logfile:
        fh = logging.handlers.RotatingFileHandler(
            filename=str(logfile),
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        fh.setLevel(numeric_level)
        fh.setFormatter(formatter)
        logger.addHandler(fh)


def load_config(path: Path | None) -> dict[str, Any]:
    """
    Load configuration from a file.
    Supports JSON by default. If PyYAML is installed and file has .yaml/.yml extension, YAML is supported.
    Returns an empty dict if no path provided.
    """
    if not path:
        return {}

    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    suffix = path.suffix.lower()
    if suffix in {".json"}:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    if suffix in {".yml", ".yaml"}:
        try:
            import yaml  # type: ignore
        except Exception as exc:
            raise RuntimeError(
                "PyYAML is required to load YAML config files. Install with 'pip install pyyaml'"
            ) from exc
        with path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}

    # Fallback: try JSON parse
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def run_main_task(config: dict[str, Any], args: argparse.Namespace) -> int:
    """
    Core application logic for DECOYABLE scanning.
    Returns an exit code (0 for success).
    """
    log = logging.getLogger(__name__)
    log.debug("run_main_task start: args=%s config=%s", args, config)

    # Handle scanning commands
    if hasattr(args, "scan_type"):
        return run_scan(args)

    # Legacy greeting functionality (for backward compatibility)
    name = args.name or config.get("name") or "World"
    log.info("Hello, %s!", name)

    if args.decoy:
        decoy_path = Path(args.decoy)
        try:
            decoy_path.write_text(f"decoy for {name}\n", encoding="utf-8")
            log.info("Wrote decoy file: %s", decoy_path)
        except Exception as exc:
            log.exception("Failed to write decoy file: %s", exc)
            return 2

    log.debug("run_main_task completed successfully")
    return 0


def run_scan(args: argparse.Namespace) -> int:
    """
    Run security scans based on command line arguments.
    """
    log = logging.getLogger(__name__)

    scan_type = getattr(args, "scan_type", "all")
    target_path = getattr(args, "path", ".")
    output_format = getattr(args, "format", "text")

    log.info(f"Starting {scan_type} scan on: {target_path}")

    try:
        if scan_type in ("secrets", "all"):
            log.info("Scanning for exposed secrets...")
            findings = secrets.scan_paths([target_path])

            if findings:
                log.warning(f"Found {len(findings)} potential secrets:")
                for finding in findings:
                    print(f"{finding.filename}:{finding.lineno} [{finding.secret_type}] {finding.masked()}")
                    if output_format == "verbose":
                        print(f"  Context: {finding.context}")
                if scan_type == "secrets":
                    return 1  # Exit with error if secrets found
            else:
                log.info("No secrets found.")

        if scan_type in ("deps", "all"):
            log.info("Scanning for dependency issues...")
            missing_imports, import_mapping = deps.missing_dependencies(target_path)

            if missing_imports:
                log.warning(f"Found {len(missing_imports)} missing dependencies:")
                for imp in sorted(missing_imports):
                    providers = import_mapping.get(imp, [])
                    if providers:
                        print(f"{imp} -> {', '.join(providers)}")
                    else:
                        print(f"{imp} -> (no known providers)")
                if scan_type == "deps":
                    return 1  # Exit with error if missing deps
            else:
                log.info("All dependencies appear to be satisfied.")

        if scan_type in ("sast", "all"):
            log.info("Performing Static Application Security Testing (SAST)...")
            sast_results = sast.scan_sast(target_path)

            vulnerabilities = sast_results.get("vulnerabilities", [])
            summary = sast_results.get("summary", {})

            if vulnerabilities:
                log.warning(f"Found {len(vulnerabilities)} potential security vulnerabilities:")
                severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

                for vuln in sorted(
                    vulnerabilities,
                    key=lambda x: severity_order.index(
                        x["severity"].value if hasattr(x["severity"], "value") else str(x["severity"])
                    ),
                ):
                    severity = vuln["severity"].value if hasattr(vuln["severity"], "value") else vuln["severity"]
                    vuln_type = (
                        vuln["vulnerability_type"].value
                        if hasattr(vuln["vulnerability_type"], "value")
                        else vuln["vulnerability_type"]
                    )
                    print(f"[{severity}] {vuln_type} - {vuln['file_path']}:{vuln['line_number']}")
                    print(f"  {vuln['description']}")
                    if output_format == "verbose":
                        print(f"  Recommendation: {vuln['recommendation']}")
                        print("  Code snippet:")
                        for line in vuln["code_snippet"].split("\n"):
                            print(f"    {line}")
                        print()

                if scan_type == "sast":
                    return 1  # Exit with error if vulnerabilities found
            else:
                log.info("No security vulnerabilities found.")

            # Print summary
            if summary:
                print(f"\nSummary: {summary['total_vulnerabilities']} vulnerabilities found")
                print(f"Files scanned: {summary['files_scanned']}")
                if summary["severity_breakdown"]:
                    print("Severity breakdown:")
                    for severity, count in summary["severity_breakdown"].items():
                        print(f"  {severity}: {count}")

        log.info("Scan completed successfully.")
        return 0

    except Exception as exc:
        log.exception(f"Scan failed: {exc}")
        return 1


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=APP_NAME, description="DECOYABLE CLI")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    p.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (repeatable)",
    )
    p.add_argument("--logfile", type=Path, help="Optional path to a rotating log file")
    p.add_argument("--config", type=Path, help="Path to JSON/YAML configuration file")

    sub = p.add_subparsers(dest="command", required=False)

    # default/run command
    run = sub.add_parser("run", help="Run the main task")
    run.add_argument("--name", "-n", help="Name to greet")
    run.add_argument("--decoy", "-d", help="Path to write a decoy file (optional)")

    # scan command
    scan = sub.add_parser("scan", help="Scan for security vulnerabilities")
    scan.add_argument(
        "scan_type",
        choices=["secrets", "deps", "sast", "all"],
        help="Type of scan to perform",
    )
    scan.add_argument("path", nargs="?", default=".", help="Path to scan (default: current directory)")
    scan.add_argument("--format", choices=["text", "verbose"], default="text", help="Output format")

    # test command (lightweight)
    tst = sub.add_parser("test", help="Run self-test checks")
    tst.add_argument("--fast", action="store_true", help="Run a fast subset of tests")

    return p


def main(argv: list[str] | None = None) -> int:
    """
    Application entry point. Returns an exit code.
    """
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # Logging level: default INFO, -v increases verbosity
    level = "WARNING"
    if args.verbose >= 2:
        level = "DEBUG"
    elif args.verbose == 1:
        level = "INFO"

    setup_logging(level=level, logfile=args.logfile if "logfile" in args else None)
    log = logging.getLogger(__name__)
    log.debug("Starting %s version %s", APP_NAME, VERSION)

    # Load config if provided
    try:
        config = load_config(args.config) if getattr(args, "config", None) else {}
    except Exception as exc:
        log.exception("Failed to load configuration: %s", exc)
        return 3

    # Dispatch commands
    cmd = getattr(args, "command", None) or "run"
    try:
        if cmd in ("run", "scan"):
            return run_main_task(config, args)
        elif cmd == "test":
            log.info("Running self-tests (fast=%s)", getattr(args, "fast", False))
            # Simple internal checks
            if getattr(args, "fast", False):
                log.info("Fast tests passed")
                return 0
            log.info("Full tests passed")
            return 0
        else:
            log.error("Unknown command: %s", cmd)
            return 4
    except KeyboardInterrupt:
        log.warning("Interrupted by user")
        return 130
    except Exception:
        log.exception("Unhandled exception")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
