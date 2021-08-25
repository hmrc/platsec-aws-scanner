from json import dumps
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

    def create_role(self, name: str, assume_policy: Dict[str, Any]) -> Role:
        try:
            return to_role(self._iam.create_role(RoleName=name, AssumeRolePolicyDocument=dumps(assume_policy))["Role"])
        except (BotoCoreError, ClientError) as err:
            raise IamException(
                f"unable to create role with name {name} and assume role policy document {assume_policy}: {err}"
            ) from None

    def create_policy(self, name: str, document: Dict[str, Any]) -> Policy:
        try:
            return to_policy(self._iam.create_policy(PolicyName=name, PolicyDocument=dumps(document))["Policy"])
        except (BotoCoreError, ClientError) as err:
            raise IamException(
                f"unable to create policy with name {name} and policy document {document}: {err}"
            ) from None

    def attach_role_policy(self, role_name: str, policy_arn: str) -> None:
        try:
            self._iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except (BotoCoreError, ClientError) as err:
            raise IamException(f"unable to attach role {role_name} and policy {policy_arn}: {err}") from None

    def get_role(self, name: str) -> Role:
        try:
            return self._enrich_role(to_role(self._iam.get_role(RoleName=name)["Role"]))
        except (BotoCoreError, ClientError) as err:
            raise IamException(f"unable to get role with name {name}: {err}") from None

    def get_role_by_arn(self, arn: str) -> Role:
        return self.get_role(arn.split(":")[-1].removeprefix("role/"))

    def _enrich_role(self, role: Role) -> Role:
        role.policies = [self._enrich_policy(self._get_policy(p)) for p in self._list_attached_role_policies(role.name)]
        return role

    def _list_attached_role_policies(self, role: str) -> Sequence[str]:
        try:
            return [
                p["PolicyArn"]
                for page in self._iam.get_paginator("list_attached_role_policies").paginate(RoleName=role)
                for p in page["AttachedPolicies"]
            ]
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
