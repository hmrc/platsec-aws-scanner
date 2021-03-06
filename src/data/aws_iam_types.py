from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional, Sequence, Set

from src.data import is_list
from src.data.aws_common_types import Tag
from src.data.aws_scanner_exceptions import UnsupportedPolicyDocumentElement


@dataclass
class Role:
    name: str
    arn: str
    assume_policy: Dict[str, Any]
    policies: Sequence[Policy]
    tags: Sequence[Tag]

    def __init__(
        self,
        name: str,
        arn: str,
        assume_policy: Dict[str, Any],
        policies: Optional[Sequence[Policy]] = None,
        tags: Optional[Sequence[Tag]] = None,
    ):
        self.name = name
        self.arn = arn
        self.assume_policy = assume_policy
        self.policies = policies or []
        self.tags = tags or []


def to_role(role: Dict[Any, Any]) -> Role:
    return Role(
        name=role["RoleName"],
        arn=role["Arn"],
        assume_policy=role["AssumeRolePolicyDocument"],
        tags=[Tag(tag["Key"], tag["Value"]) for tag in role["Tags"]] if role.get("Tags") else [],
    )


@dataclass
class Policy:
    name: str
    arn: str
    default_version: str
    document: Optional[Dict[str, Any]] = None

    def doc_equals(self, doc: Dict[str, Any]) -> bool:
        unrolled = self._unroll_statements(self.document) if self.document else set()
        return unrolled == self._unroll_statements(doc)

    def _unroll_statements(self, doc: Dict[str, Any]) -> Set[Statement]:
        unrolled = set()
        statements = doc["Statement"] if is_list(doc["Statement"]) else [doc["Statement"]]
        for s in self._validate_statements(statements):
            actions = s["Action"] if is_list(s["Action"]) else [s["Action"]]
            resources = s["Resource"] if is_list(s["Resource"]) else [s["Resource"]]
            for a in actions:
                for r in resources:
                    unrolled.add(Statement(action=a, resource=r, effect=s["Effect"], condition=str(s.get("Condition"))))
        return unrolled

    @staticmethod
    def _validate_statements(statements: Sequence[Dict[str, Any]]) -> Sequence[Dict[str, Any]]:
        unsupported_elements = ["NotAction", "NotResource", "Principal", "NotPrincipal"]
        invalid_statements = [s for s in statements if any(element in s for element in unsupported_elements)]
        if invalid_statements:
            raise UnsupportedPolicyDocumentElement(f"one of {unsupported_elements} found in {invalid_statements}")
        return statements


def to_policy(policy: Dict[Any, Any]) -> Policy:
    return Policy(name=policy["PolicyName"], arn=policy["Arn"], default_version=policy["DefaultVersionId"])


@dataclass(frozen=True)
class Statement:
    action: str
    condition: Optional[str]
    effect: str
    resource: str


@dataclass
class User:
    user_name: str


@dataclass
class AccessKey:
    id: str
    user_name: str
    created: datetime
    last_used: Optional[datetime] = None


@dataclass
class PasswordPolicy:
    minimum_password_length: Optional[int]
    require_symbols: Optional[bool]
    require_numbers: Optional[bool]
    require_uppercase_chars: Optional[bool]
    require_lowercase_chars: Optional[bool]
    allow_users_to_change_password: Optional[bool]
    expire_passwords: Optional[bool]
    max_password_age: Optional[int]
    password_reuse_prevention: Optional[int]
    hard_expiry: Optional[bool]


def to_password_policy(policy_response: Dict[str, Any]) -> PasswordPolicy:
    password_policy = policy_response["PasswordPolicy"]
    return PasswordPolicy(
        minimum_password_length=password_policy.get("MinimumPasswordLength"),
        require_symbols=password_policy.get("RequireSymbols"),
        require_numbers=password_policy.get("RequireNumbers"),
        require_uppercase_chars=password_policy.get("RequireUppercaseCharacters"),
        require_lowercase_chars=password_policy.get("RequireLowercaseCharacters"),
        allow_users_to_change_password=password_policy.get("AllowUsersToChangePassword"),
        expire_passwords=password_policy.get("ExpirePasswords"),
        max_password_age=password_policy.get("MaxPasswordAge"),
        password_reuse_prevention=password_policy.get("PasswordReusePrevention"),
        hard_expiry=password_policy.get("HardExpiry"),
    )
