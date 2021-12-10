from __future__ import annotations
from dataclasses import dataclass
from typing import Optional


@dataclass
class Trail:
    name: str
    logfile_validation: Optional[LogfileValidation] = None
    logfile_encryption_at_rest: Optional[LogfileEncryption] = None


@dataclass
class LogfileValidation:
    enabled: bool = False


@dataclass
class LogfileEncryption:
    enabled: bool = False
    type: str = "cmk"
