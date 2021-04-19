from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class Bucket:
    name: str


def to_bucket(bucket: Dict[Any, Any]) -> Bucket:
    return Bucket(name=bucket["Name"])
