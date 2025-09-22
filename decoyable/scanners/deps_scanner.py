"""
Dependencies scanner implementation with dependency injection support.
"""

import asyncio
import ast
import os
from collections import defaultdict
from dataclasses import dataclass
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from decoyable.core.logging import get_logger
from decoyable.scanners.interfaces import BaseScanner, ScanReport, ScanResult, ScannerType, ScannerConfig


@dataclass
class DependencyIssue:
    """Represents a dependency-related issue."""
    issue_type: str  # "missing_import", "unused_dependency", "version_conflict"
    module_name: str
    description: str
    severity: str = "medium"  # "low", "medium", "high"
    suggestions: List[str] = None
    is_issue: bool = True

    def __post_init__(self):
        if self.suggestions is None:
            self.suggestions = []


@dataclass
class DependenciesScannerConfig:
    """Configuration for the dependencies scanner."""
    enabled: bool = True
    timeout_seconds: int = 120
    max_file_size_mb: int = 5
    exclude_patterns: List[str] = None
    check_missing_imports: bool = True
    check_unused_dependencies: bool = False
    scan_depth: int = 3  # How many levels of subdirectories to scan

    def __post_init__(self):
        if self.exclude_patterns is None:
            self.exclude_patterns = [".git", "__pycache__", "node_modules", ".venv", "venv", "build", "dist"]


class DependenciesScanner(BaseScanner):
    """Advanced dependencies scanner that analyzes Python imports and requirements."""

    def __init__(self, config: DependenciesScannerConfig):
        super().__init__(ScannerType.DEPENDENCIES, config)
        self.config: DependenciesScannerConfig = config
        self._installed_packages: Optional[Dict[str, str]] = None

    async def scan_path(self, path: Union[str, Path], **kwargs) -> ScanReport:
        """Scan a path for dependency issues."""
        start_time = asyncio.get_event_loop().time()

        try:
            path_obj = Path(path)
            if not path_obj.exists():
                raise FileNotFoundError(f"Path does not exist: {path}")

            issues = []

            if self.config.check_missing_imports:
                missing_issues = await self._check_missing_imports(path_obj)
                issues.extend(missing_issues)

            if self.config.check_unused_dependencies:
                unused_issues = await self._check_unused_dependencies(path_obj)
                issues.extend(unused_issues)

            scan_time = (asyncio.get_event_loop().time() - start_time) * 1000

            return await self._create_report(
                issues,
                scan_time,
                metadata={"missing_count": len([i for i in issues if i.issue_type == "missing_import"]),
                         "unused_count": len([i for i in issues if i.issue_type == "unused_dependency"])}
            )

        except Exception as e:
            self.logger.error(f"Error scanning dependencies in {path}: {e}")
            scan_time = (asyncio.get_event_loop().time() - start_time) * 1000
            return await self._create_report([], scan_time, ScanResult.FAILURE, {"error": str(e)})

    async def scan_content(self, content: str, filename: Optional[str] = None, **kwargs) -> List[DependencyIssue]:
        """Scan content string for import-related issues."""
        try:
            tree = ast.parse(content)
            imports = self._extract_imports_from_ast(tree)
            issues = []

            # Check for potentially problematic imports
            for imp in imports:
                if imp.startswith('__future__'):
                    continue  # Skip __future__ imports

                # Check for relative imports that might be problematic
                if imp.startswith('.'):
                    issues.append(DependencyIssue(
                        issue_type="relative_import",
                        module_name=imp,
                        description=f"Relative import '{imp}' found",
                        severity="low",
                        suggestions=["Consider using absolute imports for better maintainability"]
                    ))

            return issues

        except SyntaxError:
            return []

    async def _check_missing_imports(self, path: Path) -> List[DependencyIssue]:
        """Check for missing imports in the codebase."""
        issues = []

        # Find all Python files
        python_files = self._find_python_files(path)

        # Extract all imports
        all_imports = set()
        for file_path in python_files[:500]:  # Limit to 500 files
            try:
                if self.should_scan_file(file_path):
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    imports = await self.scan_content(content, str(file_path))
                    # Also extract basic imports
                    tree_imports = self._extract_imports_from_content(content)
                    all_imports.update(tree_imports)
            except Exception as e:
                self.logger.debug(f"Could not analyze {file_path}: {e}")

        # Check which imports are missing
        installed_packages = await self._get_installed_packages()
        missing_imports = []

        for imp in all_imports:
            if imp in ['os', 'sys', 'json', 're', 'typing', 'pathlib', 'collections', 'itertools',
                      'functools', 'operator', 'datetime', 'time', 'math', 'random', 'hashlib',
                      'urllib', 'http', 'socket', 'threading', 'multiprocessing', 'asyncio',
                      'concurrent', 'subprocess', 'tempfile', 'shutil', 'glob', 'fnmatch',
                      'linecache', 'pickle', 'copyreg', 'copy', 'pprint', 'reprlib', 'enum',
                      'numbers', 'cmath', 'decimal', 'fractions', 'statistics', 'ast', 'inspect',
                      'site', 'warnings', 'contextlib', 'abc', 'atexit', 'traceback', 'gc',
                      'inspect', 'site', 'warnings', 'weakref', 'gc', 'inspect']:
                continue  # Standard library

            if '.' in imp:
                # Check top-level package
                top_level = imp.split('.')[0]
                if top_level not in installed_packages:
                    missing_imports.append(imp)
            elif imp not in installed_packages:
                missing_imports.append(imp)

        # Create issues for missing imports
        for missing in missing_imports:
            providers = self._find_potential_providers(missing, installed_packages)
            suggestions = []
            if providers:
                suggestions.extend([f"pip install {pkg}" for pkg in providers[:3]])

            issues.append(DependencyIssue(
                issue_type="missing_import",
                module_name=missing,
                description=f"Import '{missing}' not found in installed packages",
                severity="high",
                suggestions=suggestions
            ))

        return issues

    async def _check_unused_dependencies(self, path: Path) -> List[DependencyIssue]:
        """Check for potentially unused dependencies."""
        issues = []

        # This is a simplified check - in practice, this would require
        # more sophisticated analysis of requirements.txt vs actual imports

        try:
            requirements_file = path / "requirements.txt"
            if requirements_file.exists():
                with open(requirements_file, 'r', encoding='utf-8') as f:
                    requirements = [line.strip().split('==')[0].split('>=')[0].split('<')[0].split('>')[0]
                                  for line in f if line.strip() and not line.startswith('#')]

                # For now, just flag this as informational
                issues.append(DependencyIssue(
                    issue_type="unused_dependency_check",
                    module_name="requirements.txt",
                    description=f"Found {len(requirements)} dependencies in requirements.txt",
                    severity="info",
                    suggestions=["Consider auditing requirements.txt for unused packages"],
                    is_issue=False
                ))

        except Exception as e:
            self.logger.debug(f"Could not check requirements.txt: {e}")

        return issues

    def _find_python_files(self, root: Path) -> List[Path]:
        """Recursively find .py files under root."""
        python_files = []
        ignore_dirs = set(self.config.exclude_patterns)

        for dirpath, dirnames, filenames in os.walk(root):
            # Skip ignored directories
            dirnames[:] = [d for d in dirnames if d not in ignore_dirs]

            # Limit depth
            rel_path = os.path.relpath(dirpath, root)
            if rel_path != '.' and rel_path.count(os.sep) >= self.config.scan_depth:
                dirnames[:] = []  # Don't recurse deeper
                continue

            for filename in filenames:
                if filename.endswith('.py'):
                    python_files.append(Path(dirpath) / filename)

        return python_files

    def _extract_imports_from_content(self, content: str) -> Set[str]:
        """Extract import statements from Python code."""
        imports = set()

        try:
            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split('.')[0])

        except SyntaxError:
            # Fallback: simple regex-based extraction
            import re
            import_matches = re.findall(r'^(?:from\s+(\w+)|import\s+(\w+))', content, re.MULTILINE)
            for match in import_matches:
                module = match[0] or match[1]
                if module:
                    imports.add(module.split('.')[0])

        return imports

    def _extract_imports_from_ast(self, tree: ast.AST) -> Set[str]:
        """Extract imports from AST."""
        imports = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module)

        return imports

    async def _get_installed_packages(self) -> Dict[str, str]:
        """Get installed packages and their versions."""
        if self._installed_packages is not None:
            return self._installed_packages

        try:
            packages = {}
            for dist in importlib_metadata.distributions():
                name = dist.metadata.get('Name', '').lower()
                version = dist.metadata.get('Version', '')
                if name:
                    packages[name] = version

                # Also add top-level modules
                if dist.files:
                    for file in dist.files:
                        if file.parts and len(file.parts) >= 2:
                            top_level = file.parts[0]
                            if top_level.endswith('.py') or (len(file.parts) > 1 and file.parts[1] == '__init__.py'):
                                packages[top_level] = version

            self._installed_packages = packages
            return packages

        except Exception as e:
            self.logger.warning(f"Could not get installed packages: {e}")
            return {}

    def _find_potential_providers(self, module_name: str, installed_packages: Dict[str, str]) -> List[str]:
        """Find potential package providers for a module."""
        # This is a simplified mapping - in practice, you'd want a more comprehensive mapping
        common_mappings = {
            'requests': ['requests'],
            'flask': ['flask'],
            'django': ['django'],
            'fastapi': ['fastapi'],
            'pydantic': ['pydantic', 'pydantic-settings'],
            'sqlalchemy': ['sqlalchemy'],
            'redis': ['redis'],
            'celery': ['celery'],
            'pytest': ['pytest'],
            'black': ['black'],
            'isort': ['isort'],
            'mypy': ['mypy'],
            'flake8': ['flake8'],
            'pandas': ['pandas'],
            'numpy': ['numpy'],
            'matplotlib': ['matplotlib'],
            'scikit-learn': ['scikit-learn'],
            'tensorflow': ['tensorflow'],
            'torch': ['torch'],
            'transformers': ['transformers'],
            'openai': ['openai'],
            'anthropic': ['anthropic'],
            'google': ['google-cloud', 'google-auth'],
            'boto3': ['boto3'],
            'kubernetes': ['kubernetes'],
            'docker': ['docker'],
            'click': ['click'],
            'typer': ['typer'],
            'rich': ['rich'],
            'tqdm': ['tqdm'],
            'uvicorn': ['uvicorn'],
            'gunicorn': ['gunicorn'],
        }

        return common_mappings.get(module_name, [])