from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
from src.data.aws_iam_types import Role


@dataclass
class QueryLog:
    id: str
    status: str
    log_destination: Optional[str]
    log_destination_type: Optional[str]
    log_group_name: Optional[str]
    traffic_type: str
    log_format: str
    deliver_log_role_arn: Optional[str]
    deliver_log_role: Optional[Role] = None
    log_group: Optional[QueryLog] = None


@dataclass
class Route53Zone:
    id: str
    name: str
    privateZone: bool
    queryLog: str


def to_route53Zone(key: Dict[Any, Any]) -> Route53Zone:
    return Route53Zone(id=key["Id"], name=key["Name"], privateZone=key["Config"]["PrivateZone"], queryLog="")
