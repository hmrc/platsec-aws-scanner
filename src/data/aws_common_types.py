from dataclasses import dataclass
from typing import Dict
from enum import Enum


@dataclass(frozen=True)
class Tag:
    key: str
    value: str

    def to_dict(self, key_key: str = "Key", value_key: str = "Value") -> Dict[str, str]:
        return {key_key: self.key, value_key: self.value}


class ServiceName(Enum):
    default = 0
    vpc = 1
    route53 = 2
