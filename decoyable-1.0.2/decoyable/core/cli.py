"""
DECOYABLE CLI Launcher

Generic CLI launcher that delegates to the refactored CLI service.
"""

import argparse
import importlib
import logging
import sys
from typing import Callable

LOGGER = logging.getLogger("decoyable.cli")


def configure_logging(verbose: bool) -> None:
    """Configure basic logging for the launcher."""
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    LOGGER.setLevel(level)
    # Avoid duplicate handlers if configure_logging called multiple times
    if not LOGGER.handlers:
        LOGGER.addHandler(handler)


def load_main_module() -> object | None:
    """
    Try to import the project's main module. Prefer decoyable.core.main, fall back to decoyable.main.
    Returns the imported module or None.
    """
    candidates = ["decoyable.core.main", "decoyable.main", "main"]
    for name in candidates:
        try:
            mod = importlib.import_module(name)
            LOGGER.debug("Imported module '%s'", name)
            return mod
        except Exception as exc:  # import errors, etc.
            LOGGER.debug("Could not import '%s': %s", name, exc)
    LOGGER.debug("No main module found among candidates: %s", candidates)
    return None


def find_entry_callable(mod: object) -> Callable | None:
    """
    From a module, return the best candidate callable to run.
    Looks for 'main' function.
    """
    if mod is None:
        return None

    obj = getattr(mod, "main", None)
    if callable(obj):
        LOGGER.debug(
            "Using callable 'main' from module %s",
            getattr(mod, "__name__", "<module>"),
        )
        return obj

    LOGGER.debug(
        "No callable entrypoint found in module %s",
        getattr(mod, "__name__", "<module>"),
    )
    return None


def call_entrypoint(func: Callable, namespace: argparse.Namespace, forwarded_args: list[str]) -> int:
    """
    Call the discovered entrypoint with forwarded arguments.
    """
    try:
        # Combine namespace args with forwarded args for the new CLI
        all_args = sys.argv[1:]  # Pass all original args
        LOGGER.debug("Calling entrypoint with args: %s", all_args)
        res = func(all_args)
        return int(res) if isinstance(res, int) else 0
    except Exception:
        LOGGER.exception("Entrypoint invocation failed")
        raise


def build_parser(prog: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, description="decoyable CLI launcher")
    parser.add_argument("--version", action="store_true", help="Show version information (if available)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--dry-run", action="store_true", help="Do not perform actions; for testing")
    # All unknown args will be collected and forwarded to the underlying entrypoint
    return parser


def show_version(mod: object | None) -> None:
    version = "0.1.0"  # Default version
    # Try to get version from module
    if mod is not None:
        version = getattr(mod, "__version__", version)
    if version is None:
        try:
            pkg = importlib.import_module("decoyable")
            version = getattr(pkg, "__version__", version)
        except Exception:
            pass

    print(f"decoyable: {version}")


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser(prog="decoyable")
    # parse_known_args so we can forward extras to the real main
    args, extras = parser.parse_known_args(argv)

    configure_logging(args.verbose)
    LOGGER.debug("CLI args: %s; forwarded extras: %s", args, extras)

    if args.version:
        mod = load_main_module()
        show_version(mod)
        return 0

    # Load main module and entrypoint callable
    mod = load_main_module()
    if mod is None:
        LOGGER.error("Could not find project main module")
        return 2

    entry = find_entry_callable(mod)
    if entry is None:
        LOGGER.error("No runnable entrypoint found in %s", getattr(mod, "__name__", "<module>"))
        return 3

    # Handle dry-run: if true, just print what would be called
    if args.dry_run:
        print(
            "Dry run: would call entrypoint {} with args: {}".format(
                getattr(entry, "__name__", repr(entry)), sys.argv[1:]
            )
        )
        return 0

    try:
        exit_code = call_entrypoint(entry, args, extras)
        LOGGER.debug("Entrypoint returned exit code: %s", exit_code)
        return int(exit_code) if exit_code is not None else 0
    except SystemExit as se:
        # Respect SystemExit from called code
        LOGGER.debug("Entrypoint raised SystemExit: %s", se)
        return se.code if isinstance(se.code, int) else 0
    except Exception:
        LOGGER.exception("Unhandled exception while running entrypoint")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
