from json import dumps
from logging import getLogger
from typing import Any, Dict, Optional, Sequence

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

    def attach_role_policy(self, role: Role, policy: Policy) -> Role:
        try:
            self._iam.attach_role_policy(RoleName=role.name, PolicyArn=policy.arn)
            return self.get_role(role.name)
        except (BotoCoreError, ClientError) as err:
            raise IamException(f"unable to attach role {role.name} and policy {policy.arn}: {err}") from None

    def get_role(self, name: str) -> Role:
        try:
            return self._enrich_role(to_role(self._iam.get_role(RoleName=name)["Role"]))
        except (BotoCoreError, ClientError) as err:
            raise IamException(f"unable to get role with name {name}: {err}") from None

    def get_role_by_arn(self, arn: str) -> Role:
        return self.get_role(arn.split(":")[-1].removeprefix("role/"))

    def find_role(self, name: str) -> Optional[Role]:
        try:
            return self.get_role(name)
        except IamException:
            return None

    def delete_policy(self, policy_name: str) -> None:
        arn = self._get_policy_arn(policy_name)
        for entity in self._list_entities_for_policy(arn):
            self._detach_role_policy(entity, arn)
        for version in self._list_policy_versions(arn):
            self._delete_policy_version(arn, version)
        self._delete_policy(arn)

    def _get_policy_arn(self, policy_name: str) -> str:
        try:
            return next(
                iter(
                    [
                        str(policy["Arn"])
                        for page in self._iam.get_paginator("list_policies").paginate(Scope="Local")
                        for policy in page["Policies"]
                        if policy["PolicyName"] == policy_name
                    ]
                ),
            )
        except (BotoCoreError, ClientError, StopIteration) as err:
            raise IamException(f"unable to find arn for policy {policy_name}: {err}") from None

    def _delete_policy(self, policy_arn: str) -> None:
        try:
            self._iam.delete_policy(PolicyArn=policy_arn)
        except (BotoCoreError, ClientError) as err:
            raise IamException(f"unable to delete policy {policy_arn}: {err}")

    def _list_entities_for_policy(self, policy_arn: str) -> Sequence[str]:
        try:
            return [
                role["RoleName"]
                for role in self._iam.list_entities_for_policy(PolicyArn=policy_arn, EntityFilter="Role")["PolicyRoles"]
            ]
        except (BotoCoreError, ClientError) as err:
            raise IamException(f"unable to list entities for policy {policy_arn}: {err}") from None

    def _detach_role_policy(self, role_name: str, policy_arn: str) -> None:
        try:
            self._iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except (BotoCoreError, ClientError) as err:
            raise IamException(f"unable to detach role {role_name} from policy {policy_arn}: {err}") from None

    def _list_policy_versions(self, policy_arn: str) -> Sequence[str]:
        try:
            return [
                version["VersionId"]
                for version in self._iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
                if not version["IsDefaultVersion"]
            ]
        except (BotoCoreError, ClientError) as err:
            raise IamException(f"unable to list policy versions for policy {policy_arn}: {err}") from None

    def _delete_policy_version(self, policy_arn: str, version_id: str) -> None:
        try:
            self._iam.delete_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        except (BotoCoreError, ClientError) as err:
            raise IamException(f"unable to delete version {version_id} from policy {policy_arn}: {err}") from None

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
