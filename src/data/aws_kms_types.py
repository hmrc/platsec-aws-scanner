from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence


@dataclass
class Key:
    account_id: str
    region: str
    id: str
    arn: str
    description: str
    state: str
    policy: Optional[Dict[str, Any]] = None
    tags: Optional[Sequence[Tag]] = None


def to_key(key: Dict[Any, Any]) -> Key:
    return Key(
        account_id=key["AWSAccountId"],
        region=key["Arn"].split(":")[3],
        id=key["KeyId"],
        arn=key["Arn"],
        description=key["Description"],
        state=key["KeyState"],
    )


@dataclass
class Alias:
    name: str
    arn: str
    target_key_id: Optional[str]


def to_alias(alias: Dict[str, Any]) -> Alias:
    return Alias(name=alias["AliasName"], arn=alias["AliasArn"], target_key_id=alias.get("TargetKeyId"))


@dataclass(frozen=True)
class Tag:
    key: str
    value: str


def to_tag(tag: Dict[str, Any]) -> Tag:
    return Tag(key=tag["TagKey"], value=tag["TagValue"])
