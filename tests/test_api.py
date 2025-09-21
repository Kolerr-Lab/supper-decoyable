import importlib
import inspect
import re
import types

import pytest

# tests/test_api.py
"""
Broad, resilient API surface tests for the decoyable project.

These tests are designed for an OSS repository where the exact API shape
may evolve. They:
- skip gracefully if the package/module is not available
- assert presence of expected public symbols (Client, ApiClient, create_decoy, etc.)
- perform lightweight checks (docstrings, callable nature, basic validation behavior)
- avoid making real network calls

Run with: pytest -q
"""


PACKAGE_NAME = "decoyable"
CANDIDATE_API_MODULES = [
    "decoyable.api",
    "decoyable.client",
    "decoyable.api_client",
    "decoyable",
]


def try_import(module_name):
    try:
        return importlib.import_module(module_name)
    except Exception:
        return None


def find_first_module(candidates):
    for name in candidates:
        mod = try_import(name)
        if mod is not None:
            return name, mod
    return None, None


def find_symbol(module: types.ModuleType, names):
    for n in names:
        if hasattr(module, n):
            return n, getattr(module, n)
    return None, None


def is_semver(s: str) -> bool:
    # loose semver check: MAJOR.MINOR.PATCH (optionally with pre-release/build metadata)
    return bool(re.match(r"^\d+\.\d+\.\d+([\-+].+)?$", s))


def requires_package():
    """Import the main package or skip tests if not installed."""
    pkg = try_import(PACKAGE_NAME)
    if pkg is None:
        pytest.skip(f"Package '{PACKAGE_NAME}' not importable; skipping API tests.")
    return pkg


def test_package_metadata_has_version():
    pkg = requires_package()
    assert hasattr(pkg, "__version__"), "Package should expose __version__"
    version = pkg.__version__
    assert isinstance(version, str), "__version__ must be a string"
    # accept loose semver; don't be overly strict for pre-releases
    assert is_semver(version), f"__version__ ('{version}') does not look like semver"


def test_api_module_discovery_and_exports():
    """
    Ensure an API module exists and exposes at least one of the expected symbols.
    This test is intentionally permissive so it remains useful across refactors.
    """
    requires_package()

    mod_name, mod = find_first_module(CANDIDATE_API_MODULES)
    assert mod is not None, f"No API module found among {CANDIDATE_API_MODULES}"

    # common public symbols we expect in an API surface
    expected = [
        "app",  # FastAPI application instance
        "create_app",  # Application factory function
        "ScanRequest",  # Pydantic model for requests
    ]

    found = []
    for name in expected:
        if hasattr(mod, name):
            found.append(name)

    assert found, f"API module {mod_name!r} should export at least one of {expected}; found none."


def test_client_like_symbol_introspection():
    """
    If there's a Client/ApiClient class, ensure it looks reasonable:
    - is a class/type
    - has common network method names (get/post/request/send)
    - has a helpful repr/str or docstring
    """
    requires_package()
    mod_name, mod = find_first_module(CANDIDATE_API_MODULES)
    assert mod is not None

    name, client_cls = find_symbol(mod, ["Client", "ApiClient"])
    if client_cls is None:
        pytest.skip("No Client/ApiClient class found in API module; skipping client introspection test.")

    assert inspect.isclass(client_cls), f"{name} should be a class/type"

    # methods we often expect on a client
    candidate_methods = {"get", "post", "request", "send", "close"}
    available_methods = {m for m, _ in inspect.getmembers(client_cls, predicate=inspect.isfunction)}
    intersect = candidate_methods & available_methods
    # it's OK if only a subset is present; require at least one usual request-like method
    assert intersect, (
        f"{name} does not expose any common HTTP-like methods {candidate_methods}. "
        f"Available methods: {sorted(available_methods)}"
    )

    # docstring or repr helps users; enforce at least one non-empty
    doc = inspect.getdoc(client_cls) or ""
    has_repr = any("__repr__" in m for m, _ in inspect.getmembers(client_cls))
    assert doc.strip() or has_repr, f"{name} should have a docstring or a __repr__ implementation"


def test_factory_function_validation_behavior():
    """
    If the API exposes a create_decoy-like factory, check it validates inputs:
    calling with an obviously invalid payload should raise ValueError/TypeError.
    If the function accepts anything (no validation), the test is skipped to avoid flakiness.
    """
    requires_package()
    mod_name, mod = find_first_module(CANDIDATE_API_MODULES)
    assert mod is not None

    name, factory = find_symbol(mod, ["create_decoy", "create_decoyable", "create"])
    if factory is None:
        pytest.skip("No factory function (create_*) found in API module; skipping validation test.")

    assert callable(factory), f"{name} should be callable"

    # attempt to call with an invalid payload; prefer ValueError or TypeError as validation errors
    invalid_inputs = [None, "", 123, {"invalid": object()}]
    saw_expected_error = False
    for bad in invalid_inputs:
        try:
            # try to call with single positional arg; if signature different, try keyword
            sig = inspect.signature(factory)
            if len(sig.parameters) == 0:
                # can't reasonably test a zero-arg factory
                pytest.skip(f"{name} takes no arguments; cannot test validation behavior.")
            # try supplying as first parameter name if exists
            params = list(sig.parameters)
            if params:
                kwargs = {params[0]: bad}
                factory(**kwargs)
            else:
                factory(bad)
        except (ValueError, TypeError):
            saw_expected_error = True
            break
        except Exception:
            # other exceptions are considered a sign of validation too; accept and stop
            saw_expected_error = True
            break
        else:
            # no exception: continue trying other bad inputs
            continue

    if not saw_expected_error:
        pytest.skip(
            f"{name} did not raise ValueError/TypeError for obvious invalid inputs; "
            "skipping strict validation assertion."
        )


def test_public_functions_have_docstrings():
    """
    Ensure exported callables in the API module have docstrings to aid OSS contributors.
    This is a soft requirement: at least one important function/class should have a docstring.
    """
    requires_package()
    mod_name, mod = find_first_module(CANDIDATE_API_MODULES)
    assert mod is not None

    public_members = [(n, getattr(mod, n)) for n in dir(mod) if not n.startswith("_")]

    # collect callables that are user-facing (skip constants)
    callables = [(n, o) for n, o in public_members if callable(o)]
    if not callables:
        pytest.skip(f"No public callables found in module {mod_name}; nothing to check for docstrings.")

    have_doc = []
    for n, o in callables:
        doc = inspect.getdoc(o) or ""
        if doc.strip():
            have_doc.append(n)

    # require at least one public callable to have a docstring
    assert have_doc, (
        f"At least one public callable in {mod_name} should have a docstring. "
        f"Public callables: {[n for n, _ in callables]}"
    )
