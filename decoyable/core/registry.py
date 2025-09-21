import importlib
from threading import RLock
from typing import Any, Callable, Dict, Iterable, Iterator, Optional, TypeVar

"""
decoyable.core.registry

A small, well-tested registry utility suitable for registering classes or callables
used across the project (e.g. strategy implementations, model backends, serializers).

Features:
- Register by decorator or direct call
- Optional alias support
- Safe lookup with optional import-by-string
- Thread-safe
- Intention-revealing errors on conflicts
"""


T = TypeVar("T")
_sentinel = object()


class RegistryError(RuntimeError):
    pass


class Registry:
    """
    Simple thread-safe registry mapping names -> objects.

    Example:
        registry = Registry("my-registry")

        @registry.register()
        class MyImpl: ...

        # or
        registry.add("x", obj)

        obj = registry.get("MyImpl")  # case-sensitive by default
    """

    def __init__(self, name: str) -> None:
        self._name = name
        self._lock = RLock()
        self._store: Dict[str, Any] = {}

    def add(self, key: str, obj: Any, *, force: bool = False) -> None:
        """
        Add object under key. If force is False and key exists, raises RegistryError.
        """
        if not isinstance(key, str) or not key:
            raise ValueError("key must be a non-empty string")
        with self._lock:
            if key in self._store and not force:
                raise RegistryError(f"Key '{key}' already registered in '{self._name}'")
            self._store[key] = obj

    def register(
        self, name: Optional[str] = None, *, force: bool = False
    ) -> Callable[[T], T]:
        """
        Decorator to register a callable/class.

        Usage:
            @registry.register()           # registers under obj.__name__
            @registry.register("alias")    # registers under "alias"
            @registry.register(force=True) # overwrite if exists
        """

        def decorator(obj: T) -> T:
            reg_name = name or getattr(obj, "__name__", None)
            if not reg_name:
                raise RegistryError(
                    "Could not determine registration name; provide 'name' explicitly"
                )
            self.add(reg_name, obj, force=force)
            return obj

        return decorator

    def get(self, key: str, default: Any = _sentinel) -> Any:
        """
        Return registered object for key. If not found and default is provided, returns default,
        otherwise raises KeyError.
        """
        with self._lock:
            if key in self._store:
                return self._store[key]
        # If key looks like a module path, try importing it
        if "." in key:
            try:
                imported = import_string(key)
                return imported
            except Exception:
                pass
        if default is not _sentinel:
            return default
        raise KeyError(f"'{key}' not found in registry '{self._name}'")

    def unregister(self, key: str) -> None:
        """Remove a registration; raises KeyError if missing."""
        with self._lock:
            try:
                del self._store[key]
            except KeyError:
                raise KeyError(f"'{key}' not found in registry '{self._name}'") from None

    def clear(self) -> None:
        """Clear all registrations."""
        with self._lock:
            self._store.clear()

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return key in self._store

    def __getitem__(self, key: str) -> Any:
        return self.get(key)

    def keys(self) -> Iterable[str]:
        with self._lock:
            return tuple(self._store.keys())

    def values(self) -> Iterable[Any]:
        with self._lock:
            return tuple(self._store.values())

    def items(self) -> Iterable:
        with self._lock:
            return tuple(self._store.items())

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)

    def __iter__(self) -> Iterator[str]:
        with self._lock:
            yield from list(self._store.keys())

    def as_dict(self) -> Dict[str, Any]:
        """Return a shallow copy of the registry mapping."""
        with self._lock:
            return dict(self._store)

    def __repr__(self) -> str:
        return f"<Registry {self._name} keys={list(self._store.keys())!r}>"


def import_string(dotted_path: str) -> Any:
    """
    Import a dotted module path and return the attribute/class described by the path.
    Example: "package.module:Class" or "package.module.Class"
    """
    if not isinstance(dotted_path, str):
        raise TypeError("dotted_path must be a string")

    # support "module:Class" or "module.Class"
    if ":" in dotted_path:
        module_path, attr = dotted_path.split(":", 1)
    else:
        parts = dotted_path.rsplit(".", 1)
        if len(parts) == 1:
            module_path, attr = parts[0], ""
        else:
            module_path, attr = parts

    if not attr:
        # No attribute specified; import module and return it
        return importlib.import_module(module_path)

    module = importlib.import_module(module_path)
    try:
        return getattr(module, attr)
    except AttributeError as exc:
        raise ImportError(f"Module '{module_path}' has no attribute '{attr}'") from exc
