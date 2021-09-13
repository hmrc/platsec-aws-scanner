from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class Key:
    id: str
    arn: str
    description: str
    state: str
    policy: Optional[Dict[str, Any]] = None


def to_key(key: Dict[Any, Any]) -> Key:
    return Key(id=key["KeyId"], arn=key["Arn"], description=key["Description"], state=key["KeyState"])
