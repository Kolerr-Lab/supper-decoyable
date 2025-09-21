from __future__ import annotations

import argparse
import importlib
import inspect
import logging
import sys
from typing import Callable, Optional

"""
decoyable.core.cli

Generic CLI launcher for the decoyable package.

This CLI tries to import the project's main module (decoyable.main) and run a suitable
callable (preferably `main`, `run`, or `cli`). It's intentionally generic so it can
work even if the actual main implementation varies. It provides common options like
--version, --verbose, --dry-run and forwards remaining arguments to the discovered
callable when appropriate.

Place this file at: decoyable/core/cli.py
"""


LOGGER = logging.getLogger("decoyable.cli")


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    LOGGER.setLevel(level)
    # Avoid duplicate handlers if configure_logging called multiple times
    if not LOGGER.handlers:
        LOGGER.addHandler(handler)


def load_main_module() -> object | None:
    """
    Try to import the project's main module. Prefer decoyable.main, fall back to main.
    Returns the imported module or None.
    """
    candidates = ["decoyable.main", "main"]
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
    Looks for attributes in order: main, run, cli. Falls back to a callable module-level object.
    """
    if mod is None:
        return None

    candidates = ("main", "run", "cli")
    for name in candidates:
        obj = getattr(mod, name, None)
        if callable(obj):
            LOGGER.debug(
                "Using callable '%s' from module %s",
                name,
                getattr(mod, "__name__", "<module>"),
            )
            return obj

    # If module itself is callable (rare) return it
    if callable(mod):
        LOGGER.debug(
            "Module %s is callable; using module as entrypoint",
            getattr(mod, "__name__", "<module>"),
        )
        return mod

    LOGGER.debug(
        "No callable entrypoint found in module %s",
        getattr(mod, "__name__", "<module>"),
    )
    return None


def call_entrypoint(
    func: Callable, namespace: argparse.Namespace, forwarded_args: list[str]
) -> int:
    """
    Call the discovered entrypoint with an appropriate argument pattern.
    Strategies:
    - If the callable accepts no parameters: call()
    - If it accepts exactly one parameter: pass the argparse.Namespace
    - If it accepts *args or more than one positional parameter: pass forwarded_args (list)
    - If signature is ambiguous, attempt calling with namespace, then with forwarded_args, then with no args.
    Returns exit code (0 on success). Exceptions propagate as non-zero exit codes.
    """
    sig = inspect.signature(func)
    params = sig.parameters.values()
    accepts_var_pos = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
    any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)

    try:
        # No parameters
        if len(params) == 0:
            LOGGER.debug("Calling entrypoint with no arguments")
            res = func()
            return int(res) if isinstance(res, int) else 0

        # Single positional/keyword parameter (give Namespace)
        if len(params) == 1 and not accepts_var_pos:
            LOGGER.debug("Calling entrypoint with argparse.Namespace")
            res = func(namespace)
            return int(res) if isinstance(res, int) else 0

        # Var positional or multiple params -> pass forwarded_args
        if accepts_var_pos or len(params) >= 1:
            LOGGER.debug("Calling entrypoint with forwarded args: %s", forwarded_args)
            # If the function expects keywords and we have none, still try positional
            res = func(*forwarded_args)
            return int(res) if isinstance(res, int) else 0

        # Final fallback
        LOGGER.debug("Fallback calling entrypoint with no args")
        res = func()
        return int(res) if isinstance(res, int) else 0

    except TypeError as exc:
        # Try alternative strategies before failing
        LOGGER.debug("TypeError calling entrypoint: %s", exc)
        try:
            LOGGER.debug("Attempting to call entrypoint with no args as fallback")
            res = func()
            return int(res) if isinstance(res, int) else 0
        except Exception:
            LOGGER.exception("Entrypoint invocation failed")
            raise


def build_parser(prog: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, description="decoyable CLI launcher")
    parser.add_argument(
        "--version", action="store_true", help="Show version information (if available)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Do not perform actions; for testing"
    )
    parser.add_argument(
        "--config", "-c", metavar="FILE", help="Path to a configuration file"
    )
    # All unknown args will be collected and forwarded to the underlying entrypoint
    return parser


def show_version(mod: object | None) -> None:
    version = None
    # Try common places for version info
    if mod is not None:
        version = getattr(mod, "__version__", None)
    if version is None:
        try:
            pkg = importlib.import_module("decoyable")
            version = getattr(pkg, "__version__", None)
        except Exception:
            version = None

    if version is None:
        print("decoyable: version unknown")
    else:
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
        LOGGER.error("Could not find project main module (tried decoyable.main, main)")
        return 2

    entry = find_entry_callable(mod)
    if entry is None:
        LOGGER.error(
            "No runnable entrypoint found in %s", getattr(mod, "__name__", "<module>")
        )
        return 3

    # Handle dry-run: if true, just print what would be called
    if args.dry_run:
        print(
            "Dry run: would call entrypoint {} with forwarded args: {}".format(getattr(entry, "__name__", repr(entry)), extras)
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
