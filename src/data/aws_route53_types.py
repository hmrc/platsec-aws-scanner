from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class Route53Zone:
    id: str
    name: str
    privateZone: bool
    queryLog: str


def to_route53Zone(key: Dict[Any, Any]) -> Route53Zone:
    return Route53Zone(id=key["Id"], name=key["Name"], privateZone=key["Config"]["PrivateZone"], queryLog="")
