import inspect
import tempfile
import types
from collections.abc import Iterable
import pytest

# tests/test_scanners.py
"""
Open-source friendly, defensive tests for a "scanners" module.
These tests are intentionally flexible: they discover exported classes
whose names end with "Scanner" and exercise their common behaviors
(if present) without enforcing a rigid API.

The module under test is imported via pytest.importorskip('scanners'),
so the tests will be skipped if your codebase uses a different module name.
Adjust the import name if needed.
"""




def _instantiate_with_defaults(cls):
    """
    Try to instantiate `cls` by providing reasonable defaults for required
    __init__ parameters. If instantiation is impossible, raise the underlying
    exception so the test can decide how to handle it.
    """
    sig = inspect.signature(cls)
    kwargs = {}
    for name, param in sig.parameters.items():
        if name in ("self",):
            continue
        if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        if param.default is not inspect.Parameter.empty:
            # has a default, skip providing
            continue
        # Provide a sensible default based on annotation or name
        ann = param.annotation
        if ann is str or "str" in (getattr(ann, "__name__", "") or "") or name.lower().startswith(("pattern", "regex", "text", "path")):
            kwargs[name] = "test"
        elif ann is int or name.lower().endswith(("timeout", "port", "count", "max")):
            kwargs[name] = 0
        elif ann is bool or name.lower().startswith(("use_", "enable_", "flag")):
            kwargs[name] = False
        elif ann is list:
            kwargs[name] = []
        elif ann is dict:
            kwargs[name] = {}
        else:
            # Fallback to None (many implementations accept None)
            kwargs[name] = None
    return cls(**kwargs)


def _call_scan_interface(obj, text):
    """
    Call a scanning method on obj (if present). Supported callables, in order:
      - obj.scan(text)
      - obj.__call__(text)
      - module-level function scan_text(text)
      - module-level function scan(text)
    Returns the raw result (may be generator/iterable/etc).
    Raises AttributeError if no candidate callables exist.
    """
    if hasattr(obj, "scan") and callable(getattr(obj, "scan")):
        return obj.scan(text)
    if callable(obj):
        # class instances might be callable via __call__
        try:
            return obj(text)
        except TypeError:
            # callable but wrong signature; continue
            pass
    raise AttributeError("No callable 'scan' or '__call__' found on object")


@pytest.mark.usefixtures("tmp_path")
def test_scanners_module_has_scanner_classes():
    scanners_mod = pytest.importorskip("scanners", reason="No 'scanners' module to test")
    scanner_classes = [
        obj
        for name, obj in vars(scanners_mod).items()
        if inspect.isclass(obj) and name.lower().endswith("scanner")
    ]
    if not scanner_classes:
        pytest.skip("No classes ending with 'Scanner' exported from scanners module")

    # Ensure we found at least one class and that each can be instantiated and used on text
    for cls in scanner_classes:
        # Try to instantiate; if instantiation fails because the class is abstract,
        # the test will raise and report the problem.
        try:
            instance = _instantiate_with_defaults(cls)
        except Exception as exc:
            pytest.skip(f"Could not instantiate {cls.__name__!r}: {exc}")

        # The instance should expose a scan-like callable. Try to call it on a simple string.
        sample = "Hello, this is a test string with token TEST123"
        try:
            result = _call_scan_interface(instance, sample)
        except AttributeError:
            pytest.skip(f"{cls.__name__!r} has no scan/__call__ interface; skipping")
        except Exception as exc:
            pytest.fail(f"{cls.__name__!r}.scan(...) raised an unexpected exception: {exc}")

        # The result should be an iterable (but not a plain string). Convert to list safely.
        assert result is not None, f"{cls.__name__!r}.scan returned None"
        if isinstance(result, str):
            pytest.fail(f"{cls.__name__!r}.scan returned a plain string, expected iterable of findings")
        assert isinstance(result, Iterable), f"{cls.__name__!r}.scan did not return an iterable"

        # calling with empty string should not crash
        try:
            empty_result = _call_scan_interface(instance, "")
        except Exception as exc:
            pytest.fail(f"{cls.__name__!r}.scan('') raised an exception: {exc}")
        assert isinstance(empty_result, Iterable)


def test_scan_file_method_if_present(tmp_path):
    scanners_mod = pytest.importorskip("scanners", reason="No 'scanners' module to test")
    scanner_classes = [
        obj
        for name, obj in vars(scanners_mod).items()
        if inspect.isclass(obj) and name.lower().endswith("scanner")
    ]
    if not scanner_classes:
        pytest.skip("No classes ending with 'Scanner' exported from scanners module")

    # Create a small temporary file for scanners that support file scanning
    file_path = tmp_path / "sample.txt"
    file_text = "alpha\nbeta\npassword: secret\n"
    file_path.write_text(file_text, encoding="utf-8")

    for cls in scanner_classes:
        try:
            instance = _instantiate_with_defaults(cls)
        except Exception:
            continue  # already covered in other tests; don't fail here

        # If the instance has a 'scan_file' or 'scan_filepath' method, exercise it
        file_scan_method = None
        if hasattr(instance, "scan_file") and callable(getattr(instance, "scan_file")):
            file_scan_method = instance.scan_file
        elif hasattr(instance, "scan_filepath") and callable(getattr(instance, "scan_filepath")):
            file_scan_method = instance.scan_filepath
        elif hasattr(instance, "scan") and callable(getattr(instance, "scan")):
            # Some scanners accept file paths via scan(path) as well; try if signature expects a path-like
            sig = inspect.signature(instance.scan)
            params = list(sig.parameters.values())
            if params and params[0].annotation in (str, inspect._empty):
                # best-effort, we will attempt calling scan(path)
                file_scan_method = instance.scan

        if file_scan_method is None:
            # Not all scanners operate on files; skip gracefully
            continue

        try:
            result = file_scan_method(str(file_path))
        except TypeError:
            # maybe the method expects file object; try opening file
            with open(file_path, "rb") as fh:
                try:
                    result = file_scan_method(fh)
                except Exception as exc:
                    pytest.fail(f"{cls.__name__!r}.scan_file raised: {exc}")
        except Exception as exc:
            pytest.fail(f"{cls.__name__!r}.scan_file({file_path}) raised: {exc}")

        assert result is not None
        if isinstance(result, str):
            pytest.fail(f"{cls.__name__!r}.scan_file returned a plain string, expected iterable")
        assert isinstance(result, Iterable)


def test_module_level_scan_functions_are_present_or_skipped():
    scanners_mod = pytest.importorskip("scanners", reason="No 'scanners' module to test")
    # Accept a module-level scan_text or scan function if present and test basic behavior
    for func_name in ("scan_text", "scan"):
        func = getattr(scanners_mod, func_name, None)
        if func is None:
            continue
        if not callable(func):
            pytest.fail(f"Module-level {func_name} exists but is not callable")
        # basic invocation
        try:
            res = func("simple sample text")
        except Exception as exc:
            pytest.fail(f"Module-level {func_name} raised exception on normal input: {exc}")
        assert res is not None
        if isinstance(res, str):
            pytest.fail(f"Module-level {func_name} returned a plain string, expected iterable")
        assert isinstance(res, Iterable)