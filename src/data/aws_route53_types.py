from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict



@dataclass
class Route53Zone:
    id: str
    name: str
    privateZone: bool


def to_route53Zone(key: Dict[Any, Any]) -> Route53Zone:
    return Route53Zone(
        id=key["zoneId"],
        name=key["name"],
        privateZone = key["privateZone"],
    )