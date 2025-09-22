import importlib
from threading import RLock
from typing import Any, Callable, Dict, Iterable, Iterator, Optional, TypeVar, Union, Type
import inspect

"""
decoyable.core.registry

Enhanced registry with dependency injection and service locator capabilities.
Provides clean separation between core services and optional/pluggable components.

Features:
- Service registration with automatic dependency injection
- Lazy loading to prevent circular imports
- Optional service support for pluggable features
- Thread-safe operations
- Service lifecycle management
"""

T = TypeVar("T")
_sentinel = object()


class RegistryError(RuntimeError):
    pass


class ServiceNotFoundError(RegistryError):
    pass


class CircularDependencyError(RegistryError):
    pass


# Legacy Registry class for backward compatibility
class Registry:
    """
    Simple thread-safe registry mapping names -> objects.
    Kept for backward compatibility with existing code.
    """

    def __init__(self, name: str) -> None:
        self._name = name
        self._lock = RLock()
        self._store: Dict[str, Any] = {}

    def add(self, key: str, obj: Any, *, force: bool = False) -> None:
        """Add object under key."""
        if not isinstance(key, str) or not key:
            raise ValueError("key must be a non-empty string")
        with self._lock:
            if key in self._store and not force:
                raise RegistryError(f"Key '{key}' already registered in '{self._name}'")
            self._store[key] = obj

    def register(self, name: Optional[str] = None, *, force: bool = False) -> Callable[[T], T]:
        """Decorator to register a callable/class."""
        def decorator(obj: T) -> T:
            reg_name = name or getattr(obj, "__name__", None)
            if not reg_name:
                raise RegistryError("Could not determine registration name")
            self.add(reg_name, obj, force=force)
            return obj
        return decorator

    def get(self, key: str, default: Any = _sentinel) -> Any:
        """Return registered object for key."""
        with self._lock:
            if key in self._store:
                return self._store[key]
        if default is not _sentinel:
            return default
        raise KeyError(f"'{key}' not found in registry '{self._name}'")

    def unregister(self, key: str) -> None:
        """Remove a registration."""
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


class ServiceRegistry:
    """
    Dependency injection container and service locator.

    Provides:
    - Automatic dependency injection based on type hints
    - Lazy service instantiation
    - Optional/pluggable service support
    - Service lifecycle management
    """

    def __init__(self, name: str = "service-registry"):
        self._name = name
        self._lock = RLock()
        self._services: Dict[str, Dict[str, Any]] = {}
        self._instances: Dict[str, Any] = {}
        self._resolving: set = set()  # Track services being resolved to detect cycles

    def register_instance(self, name: str, instance: Any) -> None:
        """
        Register a pre-created service instance.

        Args:
            name: Service name
            instance: The service instance
        """
        with self._lock:
            if name not in self._services:
                self._services[name] = {}

            self._services[name].update({
                'instance': instance,
                'singleton': True,
                'dependencies': []
            })

    def register(self, service_type: Type[T], implementation: Optional[Type[T]] = None,
                 name: Optional[str] = None, singleton: bool = True) -> None:
        """
        Register a service implementation.

        Args:
            service_type: The service interface/class
            implementation: The concrete implementation (defaults to service_type)
            name: Optional service name for multiple implementations
            singleton: Whether to create a single instance
        """
        if implementation is None:
            implementation = service_type

        service_name = name or service_type.__name__

        with self._lock:
            if service_name not in self._services:
                self._services[service_name] = {}

            self._services[service_name].update({
                'type': service_type,
                'implementation': implementation,
                'singleton': singleton,
                'dependencies': self._get_dependencies(implementation)
            })

    def register_factory(self, service_type: Type[T], factory: Callable[[], T],
                        name: Optional[str] = None, singleton: bool = True) -> None:
        """
        Register a service using a factory function.

        Args:
            service_type: The service interface/class
            factory: Factory function that returns the service instance
            name: Optional service name
            singleton: Whether the factory result should be cached
        """
        service_name = name or service_type.__name__

        with self._lock:
            if service_name not in self._services:
                self._services[service_name] = {}

            self._services[service_name].update({
                'type': service_type,
                'factory': factory,
                'singleton': singleton,
                'dependencies': self._get_dependencies(factory) if callable(factory) else []
            })

    def register_instance(self, name: str, instance: Any) -> None:
        """
        Register a pre-created service instance.

        Args:
            name: Service name
            instance: The service instance
        """
        with self._lock:
            if name not in self._services:
                self._services[name] = {}

            self._services[name].update({
                'instance': instance,
                'singleton': True,
                'dependencies': []
            })

    def get_by_name(self, name: str) -> Any:
        """
        Get a service instance by name.

        Args:
            name: Service name

        Returns:
            Service instance
        """
        with self._lock:
            if name not in self._services:
                raise ServiceNotFoundError(f"Service '{name}' not registered")

            service_info = self._services[name]

            # Return cached instance for singletons
            if 'instance' in service_info:
                return service_info['instance']

            # For registered instances, return them directly
            if name in self._instances:
                return self._instances[name]

            raise ServiceNotFoundError(f"Service '{name}' not instantiated")

    def get(self, service_type: Type[T], name: Optional[str] = None) -> T:
        """
        Get a service instance, resolving dependencies automatically.

        Args:
            service_type: The service type to retrieve
            name: Optional service name for multiple implementations

        Returns:
            Service instance with dependencies injected
        """
        service_name = name or service_type.__name__

        with self._lock:
            if service_name not in self._services:
                raise ServiceNotFoundError(f"Service '{service_name}' not registered")

            # Return cached instance for singletons
            if service_name in self._instances:
                return self._instances[service_name]

            # Check for circular dependency
            if service_name in self._resolving:
                raise CircularDependencyError(f"Circular dependency detected for service '{service_name}'")

            self._resolving.add(service_name)

            try:
                service_config = self._services[service_name]

                # Create instance
                if 'instance' in service_config:
                    instance = service_config['instance']
                elif 'factory' in service_config:
                    instance = service_config['factory']()
                else:
                    implementation = service_config['implementation']
                    dependencies = self._resolve_dependencies(service_config['dependencies'])
                    instance = implementation(**dependencies)

                # Cache singleton instances
                if service_config.get('singleton', True):
                    self._instances[service_name] = instance

                return instance

            finally:
                self._resolving.discard(service_name)

    def has(self, service_type: Type[T], name: Optional[str] = None) -> bool:
        """Check if a service is registered."""
        service_name = name or service_type.__name__
        with self._lock:
            return service_name in self._services

    def unregister(self, service_type: Type[T], name: Optional[str] = None) -> None:
        """Unregister a service."""
        service_name = name or service_type.__name__
        with self._lock:
            if service_name in self._services:
                del self._services[service_name]
            if service_name in self._instances:
                del self._instances[service_name]

    def clear(self) -> None:
        """Clear all services and instances."""
        with self._lock:
            self._services.clear()
            self._instances.clear()
            self._resolving.clear()

    def _get_dependencies(self, implementation: Union[Type, Callable]) -> Dict[str, Type]:
        """Extract dependency requirements from type hints."""
        if inspect.isfunction(implementation) or inspect.ismethod(implementation):
            sig = inspect.signature(implementation)
        elif inspect.isclass(implementation):
            # Get __init__ signature
            init_method = getattr(implementation, '__init__', None)
            if init_method:
                sig = inspect.signature(init_method)
                # Skip 'self' parameter
                parameters = list(sig.parameters.values())[1:]
                sig = sig.replace(parameters=parameters)
            else:
                return {}
        else:
            return {}

        dependencies = {}
        for param_name, param in sig.parameters.items():
            if param.annotation != inspect.Parameter.empty:
                dependencies[param_name] = param.annotation

        return dependencies

    def _resolve_dependencies(self, dependencies: Dict[str, Type]) -> Dict[str, Any]:
        """Resolve service dependencies."""
        resolved = {}
        for param_name, dep_type in dependencies.items():
            try:
                resolved[param_name] = self.get(dep_type)
            except ServiceNotFoundError:
                # Try to create with default constructor if no service registered
                try:
                    resolved[param_name] = dep_type()
                except TypeError:
                    raise ServiceNotFoundError(
                        f"Cannot resolve dependency '{param_name}' of type {dep_type}"
                    )
        return resolved


# Global service registry instance
_service_registry = ServiceRegistry()

def get_service_registry() -> ServiceRegistry:
    """Get the global service registry instance."""
    return _service_registry

def register_service(service_type: Type[T], implementation: Optional[Type[T]] = None,
                    name: Optional[str] = None, singleton: bool = True) -> None:
    """Register a service in the global registry."""
    _service_registry.register(service_type, implementation, name, singleton)

def get_service(service_type: Type[T], name: Optional[str] = None) -> T:
    """Get a service from the global registry."""
    return _service_registry.get(service_type, name)

def has_service(service_type: Type[T], name: Optional[str] = None) -> bool:
    """Check if a service is registered."""
    return _service_registry.has(service_type, name)
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

    def register(self, name: Optional[str] = None, *, force: bool = False) -> Callable[[T], T]:
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
                raise RegistryError("Could not determine registration name; provide 'name' explicitly")
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
            module_path, attr = ""
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


# Attack-specific registry for DECOYABLE
class AttackRegistry(Registry):
    """
    Specialized registry for attack types and patterns.
    Provides methods specific to attack detection and classification.
    """

    def __init__(self):
        super().__init__("attack-registry")

    def register_attack_type(self, attack_type: str, metadata: Dict[str, Any]) -> None:
        """Register a new attack type with metadata."""
        if not isinstance(attack_type, str) or not attack_type:
            raise ValueError("attack_type must be a non-empty string")
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be a dictionary")

        self.add(attack_type, metadata)

    def get_attack_types(self) -> Dict[str, Any]:
        """Get all registered attack types."""
        return self.as_dict()

    def is_attack_type_registered(self, attack_type: str) -> bool:
        """Check if an attack type is registered."""
        return attack_type in self
