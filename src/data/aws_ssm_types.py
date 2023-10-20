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
        return (
            self.inputs.get("s3BucketName") == other.inputs.get("s3BucketName")
            and self.inputs.get("s3EncryptionEnabled") == other.inputs.get("s3EncryptionEnabled")
            and self.inputs.get("maxSessionDuration") == other.inputs.get("maxSessionDuration")
            and self.inputs.get("shellProfile") == other.inputs.get("shellProfile")
        )
