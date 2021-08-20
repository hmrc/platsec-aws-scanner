from logging import getLogger
from typing import Any, Dict, Sequence

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from src.data.aws_iam_types import Policy, Role, to_policy, to_role
from src.data.aws_scanner_exceptions import IamException


class AwsIamClient:
    def __init__(self, boto_iam: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._iam = boto_iam

    def get_role(self, name: str) -> Role:
        try:
            return self._enrich_role(to_role(self._iam.get_role(RoleName=name)["Role"]))
        except (BotoCoreError, ClientError) as err:
            raise IamException(f"unable to get role with name {name}: {err}") from None

    def _enrich_role(self, role: Role) -> Role:
        role.policies = [self._enrich_policy(self._get_policy(p)) for p in self._list_attached_role_policies(role.name)]
        return role

    def _list_attached_role_policies(self, role: str) -> Sequence[str]:
        try:
            return [p["PolicyArn"] for p in self._iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]]
        except (BotoCoreError, ClientError) as err:
            raise IamException(f"unable to list attached role policies for role with name {role}: {err}") from None

    def _get_policy(self, arn: str) -> Policy:
        try:
            return to_policy(self._iam.get_policy(PolicyArn=arn)["Policy"])
        except (BotoCoreError, ClientError) as err:
            raise IamException(f"unable to get policy with arn {arn}: {err}") from None

    def _get_policy_document(self, arn: str, version: str) -> Dict[str, Any]:
        try:
            return dict(self._iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]["Document"])
        except (BotoCoreError, ClientError) as err:
            raise IamException(f"unable to get policy version for policy with arn {arn}: {err}") from None

    def _enrich_policy(self, policy: Policy) -> Policy:
        policy.document = self._get_policy_document(policy.arn, policy.default_version)
        return policy
