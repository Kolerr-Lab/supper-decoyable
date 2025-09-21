
from dataclasses import dataclass, field
from typing import Dict, List, Type, Any

@dataclass
class Finding:
    scanner: str
    severity: str
    message: str
    path: str | None = None
    line: int | None = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class BaseScanner:
    name = "base"
    def scan(self, target: str, **kwargs) -> List[Finding]:
        raise NotImplementedError

_REGISTRY: Dict[str, Type[BaseScanner]] = {}

def register_scanner(scanner_cls: Type[BaseScanner]):
    _REGISTRY[scanner_cls.__name__] = scanner_cls
    return scanner_cls

def get_scanners() -> List[Type[BaseScanner]]:
    return list(_REGISTRY.values())
