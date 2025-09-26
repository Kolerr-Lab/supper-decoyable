"""
DECOYABLE CLI Entry Point

Refactored CLI entry point with dependency injection and clean architecture.
"""

import argparse
import sys
from pathlib import Path
from typing import Any, Dict

from decoyable.core.cli_service import CLIService
from decoyable.core.config import Settings
from decoyable.core.logging import setup_logging_service
from decoyable.core.registry import ServiceRegistry


def load_config(path: Path | None) -> Dict[str, Any]:
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
        import json

        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        # Validate config structure
        if not isinstance(data, dict):
            raise ValueError("Configuration file must contain a JSON object")
        return data

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
    import json

    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    # Validate config structure
    if not isinstance(data, dict):
        raise ValueError("Configuration file must contain a JSON object")
    return data


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    p = argparse.ArgumentParser(prog="decoyable", description="DECOYABLE CLI")
    p.add_argument("--version", action="version", version="decoyable 1.0.3")
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

    # fix command
    fix = sub.add_parser("fix", help="Apply automated fixes for security issues")
    fix.add_argument("--scan-results", type=Path, help="Path to JSON file with scan results")
    fix.add_argument("--auto-approve", action="store_true", help="Apply fixes without confirmation")
    fix.add_argument("--confirm", action="store_true", help="Confirm before applying fixes")

    # test command (lightweight)
    tst = sub.add_parser("test", help="Run self-test checks")
    tst.add_argument("--fast", action="store_true", help="Run a fast subset of tests")

    # task command (task queue operations)
    task = sub.add_parser("task", help="Task queue operations")
    task_sub = task.add_subparsers(dest="task_command", required=True)

    # task submit
    task_submit = task_sub.add_parser("submit", help="Submit a scan task")
    task_submit.add_argument(
        "scan_type",
        choices=["secrets", "deps", "sast", "all"],
        help="Type of scan to submit",
    )
    task_submit.add_argument("path", nargs="?", default=".", help="Path to scan")

    # task status
    task_status = task_sub.add_parser("status", help="Check task status")
    task_status.add_argument("task_id", help="Task ID to check")
    task_status.add_argument("--group", action="store_true", help="Check group task status")

    # task cancel
    task_cancel = task_sub.add_parser("cancel", help="Cancel a task")
    task_cancel.add_argument("task_id", help="Task ID to cancel")

    # task stats
    task_stats = task_sub.add_parser("stats", help="Show task queue statistics")

    # streaming command (streaming operations)
    streaming = sub.add_parser("streaming", help="Streaming operations")
    streaming_sub = streaming.add_subparsers(dest="streaming_command", required=True)

    # streaming status
    streaming_status = streaming_sub.add_parser("status", help="Check streaming status")

    # streaming publish
    streaming_publish = streaming_sub.add_parser("publish", help="Publish an event")
    streaming_publish.add_argument("event_type", help="Type of event to publish")
    streaming_publish.add_argument("--data", default="{}", help="JSON event data")
    streaming_publish.add_argument("--key", help="Partitioning key")

    # streaming start
    streaming_start = streaming_sub.add_parser("start", help="Start streaming consumers")

    # streaming stop
    streaming_stop = streaming_sub.add_parser("stop", help="Stop streaming consumers")

    # streaming alert
    streaming_alert = streaming_sub.add_parser("alert", help="Publish a security alert")
    streaming_alert.add_argument("alert_type", help="Type of security alert")
    streaming_alert.add_argument(
        "--severity", choices=["low", "medium", "high", "critical"], default="medium", help="Alert severity"
    )
    streaming_alert.add_argument("--message", default="Security alert", help="Alert message")
    streaming_alert.add_argument("--source-ip", help="Source IP address")
    streaming_alert.add_argument("--details", default="{}", help="JSON alert details")

    # honeypot command (honeypot operations)
    honeypot = sub.add_parser("honeypot", help="Honeypot operations")
    honeypot_sub = honeypot.add_subparsers(dest="honeypot_command", required=True)

    # honeypot status
    honeypot_status = honeypot_sub.add_parser("status", help="Check honeypot status")

    # honeypot attacks
    honeypot_attacks = honeypot_sub.add_parser("attacks", help="Get recent attacks")
    honeypot_attacks.add_argument("--limit", type=int, default=10, help="Number of attacks to retrieve")

    # honeypot patterns
    honeypot_patterns = honeypot_sub.add_parser("patterns", help="Get attack patterns")

    # honeypot block
    honeypot_block = honeypot_sub.add_parser("block", help="Block an IP address")
    honeypot_block.add_argument("ip_address", help="IP address to block")

    # honeypot decoy
    honeypot_decoy = honeypot_sub.add_parser("decoy", help="Manage decoy endpoints")
    honeypot_decoy.add_argument("decoy_action", choices=["add"], help="Decoy action")
    honeypot_decoy.add_argument("endpoint", help="Endpoint path")

    return p


def setup_services(config_path: Path | None = None) -> tuple[Settings, ServiceRegistry, CLIService]:
    """Initialize all core services."""
    # Load configuration
    config_dict = load_config(config_path) if config_path else {}

    # Initialize core services
    config = Settings()
    registry = ServiceRegistry()
    logging_service = setup_logging_service(config)

    # Register core services
    registry.register_instance("config", config)
    registry.register_instance("logging", logging_service)
    registry.register_instance("registry", registry)

    # Initialize cache service
    try:
        from decoyable.core.cache_service import CacheService

        cache_service = CacheService(registry)
        registry.register_instance("cache_service", cache_service)
    except Exception as exc:
        logging_service.get_logger("cli").warning(f"Cache service not available: {exc}")
        cache_service = None

    # Initialize task queue service
    try:
        from decoyable.core.task_queue_service import TaskQueueService

        task_queue_service = TaskQueueService(registry)
        registry.register_instance("task_queue_service", task_queue_service)
    except Exception as exc:
        logging_service.get_logger("cli").warning(f"Task queue service not available: {exc}")

    # Initialize scanner service if available
    try:
        from decoyable.scanners.service import ScannerService

        scanner_service = ScannerService(config, logging_service, cache_service)
        registry.register_instance("scanner_service", scanner_service)
    except Exception as exc:
        # Scanner service may not be available in all configurations
        logging_service.get_logger("cli").warning(f"Scanner service not available: {exc}")

    # Initialize database service
    try:
        from decoyable.core.database_service import DatabaseService

        database_service = DatabaseService(config, registry, logging_service)
        # For now, initialize synchronously to avoid event loop issues
        # TODO: Properly handle async initialization in service startup
        registry.register_instance("database_service", database_service)
    except Exception as exc:
        logging_service.get_logger("cli").warning(f"Database service not available: {exc}")

    # Initialize streaming service
    try:
        from decoyable.core.streaming_service import StreamingService

        streaming_service = StreamingService(registry)
        registry.register_instance("streaming_service", streaming_service)
    except Exception as exc:
        logging_service.get_logger("cli").warning(f"Streaming service not available: {exc}")

    # Initialize honeypot service
    try:
        from decoyable.core.honeypot_service import HoneypotService

        honeypot_service = HoneypotService(registry)
        registry.register_instance("honeypot_service", honeypot_service)
    except Exception as exc:
        logging_service.get_logger("cli").warning(f"Honeypot service not available: {exc}")

    # Create CLI service
    cli_service = CLIService(config, registry, logging_service)
    registry.register_instance("cli_service", cli_service)

    return config, registry, cli_service


def main(argv: list[str] | None = None) -> int:
    """
    Application entry point. Returns an exit code.
    """
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # Setup services
    try:
        config, registry, cli_service = setup_services(getattr(args, "config", None))
    except Exception as exc:
        print(f"Failed to initialize services: {exc}", file=sys.stderr)
        return 3

    # Configure logging level based on verbosity
    logger = cli_service.logger
    if args.verbose >= 2:
        # Set to DEBUG level
        pass  # Already configured by logging service
    elif args.verbose == 1:
        # Set to INFO level
        pass  # Already configured by logging service

    logger.debug("Starting decoyable version 1.0.3")

    # Load additional config if provided
    try:
        config_dict = load_config(getattr(args, "config", None)) if getattr(args, "config", None) else {}
    except Exception as exc:
        logger.exception("Failed to load configuration: %s", exc)
        return 3

    # Dispatch commands
    cmd = getattr(args, "command", None) or "run"
    try:
        if cmd in ("run", "scan"):
            return cli_service.run_main_task(config_dict, args)
        elif cmd == "fix":
            return cli_service.run_fix_command(args)
        elif cmd == "test":
            return cli_service.run_test_command(args)
        elif cmd == "task":
            return cli_service.run_task_command(args)
        elif cmd == "streaming":
            return cli_service.run_streaming_command(args)
        elif cmd == "honeypot":
            return cli_service.run_honeypot_command(args)
        else:
            logger.error("Unknown command: %s", cmd)
            return 4
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        return 130
    except Exception:
        logger.exception("Unhandled exception")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
