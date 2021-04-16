from dataclasses import dataclass
from typing import Any, Dict

TYPES = ["SecureString", "StringList", "String"]


@dataclass
class Parameter:
    name: str
    type: str


def to_parameter(parameter: Dict[Any, Any]) -> Parameter:
    return Parameter(name=parameter["Name"], type=parameter["Type"])
