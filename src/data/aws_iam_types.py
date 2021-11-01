from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional, Sequence

from src.data.aws_common_types import Tag


@dataclass
class Role:
    name: str
    arn: str
    assume_policy: Dict[str, Any]
    policies: Sequence[Policy]
    tags: Sequence[Tag]

    def __init__(
        self,
        name: str,
        arn: str,
        assume_policy: Dict[str, Any],
        policies: Optional[Sequence[Policy]] = None,
        tags: Optional[Sequence[Tag]] = None,
    ):
        self.name = name
        self.arn = arn
        self.assume_policy = assume_policy
        self.policies = policies or []
        self.tags = tags or []


def to_role(role: Dict[Any, Any]) -> Role:
    return Role(
        name=role["RoleName"],
        arn=role["Arn"],
        assume_policy=role["AssumeRolePolicyDocument"],
        tags=[Tag(tag["Key"], tag["Value"]) for tag in role["Tags"]] if role.get("Tags") else [],
    )


@dataclass
class Policy:
    name: str
    arn: str
    default_version: str
    document: Optional[Dict[str, Any]] = None


def to_policy(policy: Dict[Any, Any]) -> Policy:
    return Policy(name=policy["PolicyName"], arn=policy["Arn"], default_version=policy["DefaultVersionId"])


@dataclass
class User:
    user_name: str


@dataclass
class AccessKey:
    id: str
    user_name: str
    created: datetime
    last_used: Optional[datetime] = None
