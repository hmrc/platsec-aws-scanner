from dataclasses import dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class Tag:
    key: str
    value: str


def to_tag(tag: Dict[str, Any]) -> Tag:
    return Tag(key=tag["TagKey"], value=tag["TagValue"])
