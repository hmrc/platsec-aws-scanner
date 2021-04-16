from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class Account:
    identifier: str
    name: str

    def __str__(self) -> str:
        return f"{self.name} ({self.identifier})"

    @classmethod
    def to_account(cls, account_dict: Dict[Any, Any]) -> Account:
        return cls(identifier=account_dict["Id"], name=account_dict["Name"])


@dataclass
class OrganizationalUnit:
    identifier: str
    name: str
    root: bool
    accounts: List[Account]
    org_units: List[Any]

    def __str__(self) -> str:
        return f"{self.name} ({self.identifier})"

    @classmethod
    def to_org_unit(cls, org_unit_dict: Dict[Any, Any]) -> OrganizationalUnit:
        return cls(identifier=org_unit_dict["Id"], name=org_unit_dict["Name"], root=False, accounts=[], org_units=[])

    @classmethod
    def to_root_org_unit(cls, org_unit_dict: Dict[Any, Any]) -> OrganizationalUnit:
        return cls(identifier=org_unit_dict["Id"], name=org_unit_dict["Name"], root=True, accounts=[], org_units=[])
