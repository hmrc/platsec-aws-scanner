from dataclasses import dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class Tag:
    key: str
    value: str

    def to_dict(self, key_key: str = "Key", value_key: str = "Value") -> Dict[str, str]:
        return {key_key: self.key, value_key: self.value}


def to_tag(tag: Dict[str, Any]) -> Tag:
    return Tag(key=tag["TagKey"], value=tag["TagValue"])
