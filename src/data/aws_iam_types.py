from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence


@dataclass
class Role:
    name: str
    arn: str
    assume_policy: Dict[str, Any]
    policies: Optional[Sequence[Policy]] = None


def to_role(role: Dict[Any, Any]) -> Role:
    return Role(name=role["RoleName"], arn=role["Arn"], assume_policy=role["AssumeRolePolicyDocument"])


@dataclass
class Policy:
    name: str
    arn: str
    default_version: str
    document: Optional[Dict[str, Any]] = None


def to_policy(policy: Dict[Any, Any]) -> Policy:
    return Policy(name=policy["PolicyName"], arn=policy["Arn"], default_version=policy["DefaultVersionId"])
