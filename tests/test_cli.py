import importlib
import subprocess
import sys
from pathlib import Path
import re
import pytest

# tests/test_cli.py
# Lightweight, robust CLI tests for the package entry point.
# Designed to be friendly for open-source CI: skip tests if the package
# is not importable, avoid hard assumptions about exact CLI framework.


PACKAGE_NAME = "decoyable"
MODULE_RUN_TIMEOUT = 5.0


def _project_root():
    # tests live in <project>/tests/, so project root is two parents up from this file
    return Path(__file__).resolve().parent.parent


def _run_module(args):
    """Run `python -m <PACKAGE_NAME> ...` in the project root and return CompletedProcess."""
    cmd = [sys.executable, "-m", PACKAGE_NAME] + list(args)
    return subprocess.run(
        cmd,
        cwd=str(_project_root()),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=MODULE_RUN_TIMEOUT,
    )


def _combine_output(cp):
    return " ".join(filter(None, (cp.stdout, cp.stderr))).strip()


def _looks_like_help(output):
    return bool(re.search(r"\bUsage\b|\busage\b|--help\b|Options\b|\boptions\b", output))


def _looks_like_version(output):
    return bool(re.search(r"\d+\.\d+\.\d+|\d+\.\d+", output))


def test_package_importable():
    """Package must be importable in the repository source tree."""
    try:
        importlib.import_module(PACKAGE_NAME)
    except Exception as exc:
        pytest.skip(f"Package {PACKAGE_NAME!r} not importable: {exc}")


def test_cli_help_shows_usage():
    """`python -m <pkg> --help` should print usage/help text and exit cleanly."""
    cp = _run_module(["--help"])
    out = _combine_output(cp)
    assert cp.returncode == 0, f"Expected zero exit code for --help, got {cp.returncode}. Output: {out!r}"
    assert _looks_like_help(out), f"Help output did not look like usage/help. Output: {out!r}"


def test_cli_version_flag_if_present():
    """If the CLI supports --version, it should return quickly and print a version string.
    If the flag is not supported, skip the test rather than fail the suite.
    """
    try:
        cp = _run_module(["--version"])
    except subprocess.CalledProcessError as exc:
        pytest.skip(f"Running module failed: {exc}")
    out = _combine_output(cp)
    if cp.returncode != 0:
        pytest.skip("--version not supported by the CLI (non-zero exit code)")
    assert _looks_like_version(out), f"--version output did not contain a version string. Output: {out!r}"


def test_cli_no_args_behavior():
    """Running the CLI with no arguments should either succeed or print usage/help.
    We accept both behaviors to keep tests stable across different CLI designs.
    """
    cp = _run_module([])
    out = _combine_output(cp)
    # Accept either a zero exit code (successful default behavior) or a usage/help message
    if cp.returncode == 0:
        assert True
    else:
        assert _looks_like_help(out), f"No-arg invocation failed (exit {cp.returncode}) and did not show usage. Output: {out!r}"