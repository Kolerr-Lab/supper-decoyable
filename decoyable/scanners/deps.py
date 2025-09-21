from __future__ import annotations

import argparse
import ast
import os
import sys
from collections import defaultdict
from importlib import metadata as importlib_metadata
from typing import Iterable

"""
decoyable.scanners.deps

Utility helpers to discover Python dependencies used by a project.

This is a best-effort, offline-safe scanner:
- extracts imports from .py files (using ast)
- reads requirements.txt (if present)
- inspects installed distributions to map imports -> packages

If you want me to adapt this precisely to your main.py, paste main.py here and
I'll update this file to match the expected API.
"""


# Compatibility: importlib_metadata backport is not required here because
# we already import importlib.metadata as importlib_metadata above.
# (This placeholder keeps intent clear and avoids an empty try/except block.)

__all__ = [
    "find_python_files",
    "extract_imports_from_file",
    "collect_imports_from_dir",
    "parse_requirements",
    "installed_packages",
    "map_imports_to_packages",
    "missing_dependencies",
    "write_requirements",
]


def find_python_files(
    root: str, ignore_dirs: Iterable[str] | None = None
) -> list[str]:
    """Recursively find .py files under root, skipping common virtualenv/build dirs."""
    ignore_dirs = set(
        ignore_dirs or {"venv", ".venv", "__pycache__", "build", "dist", ".git"}
    )
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        # modify dirnames in-place to skip ignored dirs
        dirnames[:] = [d for d in dirnames if d not in ignore_dirs]
        for fn in filenames:
            if fn.endswith(".py"):
                files.append(os.path.join(dirpath, fn))
    return files


def extract_imports_from_file(path: str) -> set[str]:
    """Return top-level module names imported in a .py file (e.g. 'os', 'requests')."""
    try:
        with open(path, encoding="utf-8") as fh:
            node = ast.parse(fh.read(), filename=path)
    except (SyntaxError, UnicodeDecodeError, OSError):
        return set()

    imports: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Import):
            for alias in n.names:
                top = alias.name.split(".")[0]
                imports.add(top)
        elif isinstance(n, ast.ImportFrom):
            # skip relative imports (module is None or starts with '.')
            if n.module and not n.level:
                top = n.module.split(".")[0]
                imports.add(top)
    return imports


def collect_imports_from_dir(
    root: str, ignore_dirs: Iterable[str] | None = None
) -> set[str]:
    """Scan a directory and return a set of imported top-level modules."""
    files = find_python_files(root, ignore_dirs=ignore_dirs)
    imports: set[str] = set()
    for f in files:
        imports.update(extract_imports_from_file(f))
    return imports


def parse_requirements(path: str) -> list[str]:
    """Parse a requirements-style file (simple parsing: ignores comments and editable lines)."""
    reqs: list[str] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                # skip editable or VCS lines for this simple parser
                if line.startswith("-e ") or "git+" in line or "://" in line:
                    continue
                # strip extras/environment markers (basic)
                if ";" in line:
                    line = line.split(";", 1)[0].strip()
                reqs.append(line)
    except OSError:
        pass
    return reqs


def installed_packages() -> dict[str, str]:
    """
    Return a mapping of distribution name -> version for installed packages.
    Uses importlib.metadata for the current environment.
    """
    pkgs: dict[str, str] = {}
    for dist in importlib_metadata.distributions():
        try:
            md = getattr(dist, "metadata", None)
            if md and "Name" in md:
                name = md["Name"]
            elif md and "name" in md:
                # prefer explicit indexing rather than .get() because PackageMetadata may not implement .get
                name = md["name"]
            else:
                name = ""
        except Exception:
            name = getattr(dist, "name", None) or ""
        if not name:
            # fallback: use dist.metadata key or distribution id
            md = getattr(dist, "metadata", {})
            if isinstance(md, dict):
                name = md.get("Name", "") or getattr(dist, "name", "")
            else:
                # md may be a PackageMetadata-like object: check membership then index
                if md and "Name" in md:
                    name = md["Name"]
                else:
                    name = getattr(dist, "name", "")
        name = name.strip()
        version = getattr(dist, "version", "")
        if name:
            pkgs[name] = version
    return pkgs


def _top_level_modules_for_distribution(
    dist: importlib_metadata.Distribution,
) -> set[str]:
    """
    Heuristic: read top_level.txt from metadata to find top-level modules provided by package.
    """
    modules: set[str] = set()
    try:
        # metadata_files or read_text depending on importlib version
        text = None
        for name in ("top_level.txt", "top_level"):
            try:
                text = dist.read_text(name)
                if text:
                    break
            except Exception:
                text = None
        if not text:
            # fallback: look in distribution.files for top-level names (best-effort)
            if dist.files:
                for p in dist.files:
                    parts = p.parts
                    if len(parts) == 1 and parts[0].endswith(".py"):
                        modules.add(os.path.splitext(parts[0])[0])
                    elif len(parts) >= 1 and not parts[0].startswith("."):
                        modules.add(parts[0])
            return modules
        for line in text.splitlines():
            line = line.strip()
            if line:
                modules.add(line.split()[0])
    except Exception:
        pass
    return modules


def map_imports_to_packages(imports: Iterable[str]) -> dict[str, list[str]]:
    """
    Map each import name to a list of distributions that appear to provide it.
    This is a heuristic using each distribution's top_level.txt metadata.
    """
    mapping: dict[str, list[str]] = defaultdict(list)
    imports_set = set(imports)
    # build inverted index: top-level module -> list of distributions
    tld_to_dists: dict[str, list[str]] = defaultdict(list)
    for dist in importlib_metadata.distributions():
        try:
            # Prefer metadata 'Name' if present; avoid calling .get() on PackageMetadata
            md = getattr(dist, "metadata", None)
            if md and ("Name" in md):
                dist_name = md["Name"]
            else:
                # fallback to distribution attribute 'name' if available
                dist_name = getattr(dist, "name", None) or ""
        except Exception:
            dist_name = getattr(dist, "name", "")
        if not dist_name:
            continue
        modules = _top_level_modules_for_distribution(dist)
        for m in modules:
            if m:
                tld_to_dists[m].append(dist_name)

    for imp in imports_set:
        if imp in tld_to_dists:
            mapping[imp] = sorted(set(tld_to_dists[imp]))
        else:
            # try direct package name match (import name might equal distribution name)
            candidates = list(tld_to_dists.get(imp, []))
            mapping[imp] = candidates
    return mapping


def missing_dependencies(
    project_root: str, requirements_path: str | None = None
) -> tuple[set[str], dict[str, list[str]]]:
    """
    Return (missing_imports, mapping) where:
      - missing_imports: imports found in project that are not satisfied by installed packages or requirements
      - mapping: import -> possible distributions that provide it (may be empty)
    If requirements_path is given, entries there are considered 'present' even if not installed.
    """
    imports = collect_imports_from_dir(project_root)
    reqs = set(parse_requirements(requirements_path)) if requirements_path else set()

    installed = installed_packages()
    installed_names = set(installed.keys())

    mapping = map_imports_to_packages(imports)

    missing: set[str] = set()
    for imp in imports:
        providers = mapping.get(imp, [])
        satisfied = False
        # if any provider is installed, it's satisfied
        for p in providers:
            if p in installed_names:
                satisfied = True
                break
            # sometimes requirement entries are lowercase or just package names:
            if any(p.lower() in r.lower() or r.lower() in p.lower() for r in reqs):
                satisfied = True
                break
        # also if import equals an installed package name (best-effort)
        if imp in installed_names:
            satisfied = True
        if not satisfied:
            missing.add(imp)
    return missing, mapping


def write_requirements(packages: Iterable[str], output_path: str) -> None:
    """Write a simple requirements file (one package per line)."""
    with open(output_path, "w", encoding="utf-8") as fh:
        for p in packages:
            fh.write(p.rstrip() + "\n")


# Optional convenience: simple CLI when run as a script
def _main_cli(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]

    ap = argparse.ArgumentParser(
        description="Scan a Python project for imports and missing deps."
    )
    ap.add_argument("project_root", nargs="?", default=".", help="Project root to scan")
    ap.add_argument("--requirements", "-r", help="requirements.txt path to consider")
    ap.add_argument(
        "--write", "-w", help="write missing packages (heuristic) to this file"
    )
    args = ap.parse_args(argv)

    missing, mapping = missing_dependencies(args.project_root, args.requirements)
    if not missing:
        print("No missing top-level imports detected (heuristic scan).")
    else:
        print("Missing imports (heuristic):")
        for imp in sorted(missing):
            providers = mapping.get(imp) or []
            print(
                f"  {imp} -> suggestions: {', '.join(providers) or '<no suggestion>'}"
            )
        if args.write:
            # flatten suggestions: pick first suggestion or the import name itself
            chosen = []
            for imp in sorted(missing):
                providers = mapping.get(imp) or []
                chosen.append(providers[0] if providers else imp)
            write_requirements(chosen, args.write)
            print("Wrote", args.write)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main_cli())
