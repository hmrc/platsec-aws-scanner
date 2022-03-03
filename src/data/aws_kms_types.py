from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence

from src.data.aws_common_types import Tag


@dataclass
class Key:
    account_id: str
    region: str
    id: str
    arn: str
    description: str
    state: str
    rotation_enabled: bool = None
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
