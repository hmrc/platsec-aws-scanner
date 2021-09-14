from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class Key:
    account_id: str
    region: str
    id: str
    arn: str
    description: str
    state: str
    policy: Optional[Dict[str, Any]] = None


def to_key(key: Dict[Any, Any]) -> Key:
    return Key(
        account_id=key["AWSAccountId"],
        region=key["Arn"].split(":")[3],
        id=key["KeyId"],
        arn=key["Arn"],
        description=key["Description"],
        state=key["KeyState"],
    )
