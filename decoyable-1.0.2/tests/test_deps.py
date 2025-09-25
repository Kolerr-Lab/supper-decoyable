import re
from pathlib import Path

import pytest

# tests/test_deps.py
"""
Tests to validate dependency declarations for OSS readiness.

- Parses pyproject.toml (PEP 621 or Poetry) if present and ensures dependencies
    are not declared as local paths or private VCS URLs.
- Parses requirements.txt if present and ensures no local paths, SSH URLs,
    or embedded credentials are present.

These tests are conservative: they skip when the corresponding files or
parsing libraries are not available.
"""


ROOT = Path(__file__).resolve().parents[1]


def _load_toml(path: Path):
    text = path.read_text(encoding="utf8")
    # Use stdlib tomllib on Python >=3.11, else try third-party toml
    try:
        import tomllib  # type: ignore
    except Exception:
        try:
            import toml  # type: ignore
        except Exception:
            pytest.skip("No TOML parser available (tomllib or toml).")
        else:
            return toml.loads(text)
    else:
        return tomllib.loads(text)


def _collect_pyproject_dependencies(data):
    deps = []

    # PEP 621 [project]
    project = data.get("project") if isinstance(data, dict) else None
    if project:
        # dependencies: list[str]
        for k in ("dependencies", "optional-dependencies"):
            if k in project:
                val = project[k]
                if isinstance(val, dict):
                    # optional-dependencies is a dict of lists
                    for lst in val.values():
                        if isinstance(lst, list):
                            deps.extend([str(i) for i in lst])
                elif isinstance(val, list):
                    deps.extend([str(i) for i in val])

    # Poetry [tool.poetry]
    tool = data.get("tool") if isinstance(data, dict) else None
    if tool and isinstance(tool, dict):
        poetry = tool.get("poetry")
        if poetry and isinstance(poetry, dict):
            for section in ("dependencies", "dev-dependencies"):
                sect = poetry.get(section)
                if isinstance(sect, dict):
                    for name, value in sect.items():
                        # value can be a string version, or a table (dict) for git/path
                        if isinstance(value, str):
                            deps.append(f"{name} {value}")
                        elif isinstance(value, dict):
                            # Represent dict entries in a compact form for checks
                            # Keep the dict itself to inspect keys later.
                            deps.append({name: value})
                        else:
                            deps.append(f"{name} {value!r}")
    return deps


def _is_vcs_or_local_entry(entry):
    """
    Return (True, reason) if the dependency entry indicates a VCS/path/local spec.
    """
    # If entry is a dict (from poetry), check for git/path keys
    if isinstance(entry, dict):
        # example: {'mypkg': {'git': 'https://...'}}
        name, info = next(iter(entry.items()))
        if isinstance(info, dict):
            if "git" in info or "svn" in info or "hg" in info:
                return (
                    True,
                    f"{name} uses VCS ({', '.join(k for k in info.keys() if k in ('git', 'svn', 'hg'))})",
                )
            if "path" in info:
                return True, f"{name} uses local path"
        # fallback to string representation
        entry = f"{name} {info!r}"

    if not isinstance(entry, str):
        entry = str(entry)

    s = entry.strip()

    # common VCS prefixes
    if s.startswith("git+") or s.startswith("ssh+") or s.startswith("hg+") or s.startswith("svn+"):
        return True, "starts with VCS scheme"

    # file scheme or local path indicators
    if "file://" in s or s.startswith("file:"):
        return True, "file:// or file: scheme used"
    if s.startswith(("./", "../")) or re.search(r"(^|\s)(\./|\.\./)", s):
        return True, "local relative path used"
    if re.search(r"(^|\s)/", s) and (s.startswith("/") or re.search(r"\s+/", s)):
        # absolute path used; catch lines that reference local filesystem absolutely
        return True, "absolute local path used"

    # embedded credentials in URL (e.g., https://user:token@host/... )
    if re.search(r"://[^/@\s]+:[^/@\s]+@", s):
        return True, "embedded credentials in URL"

    # git+https with token in URL (e.g., git+https://token@github.com/...)
    if "git+https://" in s and "@" in s:
        return True, "git+https with embedded credentials"

    return False, ""


def _read_requirements(path: Path):
    lines = []
    for raw in path.read_text(encoding="utf8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # keep whole line for detailed checks
        lines.append(line)
    return lines


def test_pyproject_toml_dependencies_safe():
    pyproject = ROOT / "pyproject.toml"
    if not pyproject.exists():
        pytest.skip("pyproject.toml not found")
    data = _load_toml(pyproject)
    deps = _collect_pyproject_dependencies(data)
    bad = []
    for d in deps:
        is_bad, reason = _is_vcs_or_local_entry(d)
        if is_bad:
            bad.append((d, reason))
    assert not bad, "Disallowed dependency declarations found in pyproject.toml:\n" + "\n".join(
        f"- {item!r}: {reason}" for item, reason in bad
    )


def test_requirements_txt_safe():
    req = ROOT / "requirements.txt"
    if not req.exists():
        pytest.skip("requirements.txt not found")
    lines = _read_requirements(req)
    bad = []
    for line in lines:
        # editable installs that point at local directories e.g. -e .
        if line.startswith("-e ") or line.startswith("--editable "):
            target = line.split(maxsplit=1)[1] if " " in line else ""
            if target.startswith(("./", "../", "/")) or target == ".":
                bad.append((line, "editable local path"))
                continue
        is_bad, reason = _is_vcs_or_local_entry(line)
        if is_bad:
            bad.append((line, reason))
    assert not bad, "Disallowed entries found in requirements.txt:\n" + "\n".join(
        f"- {line!r}: {reason}" for line, reason in bad
    )
