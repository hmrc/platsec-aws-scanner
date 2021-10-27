from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class Tag:
    key: str
    value: str

    def to_dict(self, key_key: str = "Key", value_key: str = "Value") -> Dict[str, str]:
        return {key_key: self.key, value_key: self.value}
