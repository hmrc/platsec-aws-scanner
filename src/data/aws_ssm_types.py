from dataclasses import dataclass
from typing import Any, Dict

TYPES = ["SecureString", "StringList", "String"]


@dataclass
class Parameter:
    name: str
    type: str


def to_parameter(parameter: Dict[Any, Any]) -> Parameter:
    return Parameter(name=parameter["Name"], type=parameter["Type"])


@dataclass
class SSMDocument:
    schema_version: str
    description: str
    session_type: str
    inputs: Dict[str, Any]

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SSMDocument):
            return False
        return self.inputs == other.inputs
