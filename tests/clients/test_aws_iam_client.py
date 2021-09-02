from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, call, patch

from typing import Any, Dict

from src.clients.aws_iam_client import AwsIamClient
from src.data.aws_scanner_exceptions import IamException

from tests.clients.test_aws_iam_client_responses import (
    EXPECTED_ROLE,
    GET_POLICY,
    GET_POLICY_VERSION,
    GET_ROLE,
    LIST_ATTACHED_ROLE_POLICIES,
)
from tests.test_types_generator import client_error, policy, role


class TestAwsIamClient(AwsScannerTestCase):
    @staticmethod
    def get_role(**kwargs) -> Dict[str, Any]:
        return GET_ROLE if kwargs["RoleName"] == "a_role" else None

    @staticmethod
    def list_attached_role_policies_paginator() -> Mock:
        return Mock(
            paginate=Mock(side_effect=lambda **k: [LIST_ATTACHED_ROLE_POLICIES] if k["RoleName"] == "a_role" else None)
        )

    @staticmethod
    def get_policy(**kwargs) -> Dict[str, Any]:
        return GET_POLICY if kwargs["PolicyArn"] == "arn:aws:iam::112233445566:policy/a_policy" else None

    @staticmethod
    def get_policy_version(**kwargs) -> Dict[str, Any]:
        return (
            GET_POLICY_VERSION
            if kwargs["PolicyArn"] == "arn:aws:iam::112233445566:policy/a_policy" and kwargs["VersionId"] == "v3"
            else None
        )

    def test_get_role(self) -> None:
        mock_boto_iam = Mock(
            get_role=Mock(side_effect=self.get_role),
            get_policy=Mock(side_effect=self.get_policy),
            get_policy_version=Mock(side_effect=self.get_policy_version),
            get_paginator=Mock(
                side_effect=lambda op: self.list_attached_role_policies_paginator()
                if op == "list_attached_role_policies"
                else None
            ),
        )
        self.assertEqual(EXPECTED_ROLE, AwsIamClient(mock_boto_iam).get_role("a_role"))

    def test_get_role_by_arn(self) -> None:
        client = AwsIamClient(Mock())
        with patch.object(AwsIamClient, "get_role") as get_role:
            client.get_role_by_arn("arn:aws:iam::account:role/some_role")
            client.get_role_by_arn("arn:aws:iam:region:account:role/with/path")
            client.get_role_by_arn("not_an_arn_works_too")
        self.assertEqual([call("some_role"), call("with/path"), call("not_an_arn_works_too")], get_role.mock_calls)

    def test_get_role_failure(self) -> None:
        mock_boto_iam = Mock(get_role=Mock(side_effect=client_error("GetRole", "NoSuchEntity", "not found")))
        with self.assertRaisesRegex(IamException, "a_role"):
            AwsIamClient(mock_boto_iam).get_role("a_role")

    def test_find_role(self) -> None:
        a_role = role("a_role")
        with patch.object(AwsIamClient, "get_role", side_effect=lambda r: a_role if r == a_role.name else None):
            self.assertEqual(a_role, AwsIamClient(Mock()).find_role("a_role"))

    def test_find_role_not_found(self) -> None:
        with patch.object(AwsIamClient, "get_role", side_effect=IamException):
            self.assertIsNone(AwsIamClient(Mock()).find_role("a_role"))

    def test_list_attached_role_policies_failure(self) -> None:
        mock_boto_iam = Mock(
            get_paginator=Mock(
                return_value=Mock(
                    paginate=Mock(side_effect=client_error("ListAttachedRolePolicies", "NoSuchEntity", "not found"))
                )
            )
        )
        with self.assertRaisesRegex(IamException, "a_role"):
            AwsIamClient(mock_boto_iam)._list_attached_role_policies("a_role")

    def test_get_policy_failure(self) -> None:
        mock_boto_iam = Mock(get_policy=Mock(side_effect=client_error("GetPolicy", "NoSuchEntity", "not found")))
        with self.assertRaisesRegex(IamException, "a_policy"):
            AwsIamClient(mock_boto_iam)._get_policy("a_policy")

    def test_get_policy_document_failure(self) -> None:
        mock_boto_iam = Mock(
            get_policy_version=Mock(side_effect=client_error("GetPolicyVersion", "NoSuchEntity", "not found"))
        )
        with self.assertRaisesRegex(IamException, "a_policy"):
            AwsIamClient(mock_boto_iam)._get_policy_document("a_policy", "v3")

    def test_create_role(self) -> None:
        name, arn, assume_policy = "a_name", "an_arn", {"key": "val"}
        mock_boto_iam = Mock(
            create_role=Mock(
                return_value={"Role": {"RoleName": name, "Arn": arn, "AssumeRolePolicyDocument": assume_policy}}
            )
        )
        created = AwsIamClient(mock_boto_iam).create_role(name, assume_policy)
        self.assertEqual(role(name=name, arn=arn, assume_policy=assume_policy, policies=[]), created)
        mock_boto_iam.create_role.assert_called_once_with(RoleName=name, AssumeRolePolicyDocument='{"key": "val"}')

    def test_create_role_failure(self) -> None:
        mock_boto_iam = Mock(create_role=Mock(side_effect=client_error("CreateRole", "EntityAlreadyExists", "failed")))
        with self.assertRaisesRegex(IamException, "a_role"):
            AwsIamClient(mock_boto_iam).create_role("a_role", {})

    def test_create_policy(self) -> None:
        name, arn, version, document = "a_name", "an_arn", "v2", {"key": "val"}
        mock_boto_iam = Mock(
            create_policy=Mock(return_value={"Policy": {"PolicyName": name, "Arn": arn, "DefaultVersionId": version}})
        )
        created = AwsIamClient(mock_boto_iam).create_policy(name, document)
        self.assertEqual(policy(name=name, arn=arn, default_version=version), created)
        mock_boto_iam.create_policy.assert_called_once_with(PolicyName=name, PolicyDocument='{"key": "val"}')

    def test_create_policy_failure(self) -> None:
        mock_boto_iam = Mock(create_policy=Mock(side_effect=client_error("CreatePolicy", "EntityAlreadyExists", "no")))
        with self.assertRaisesRegex(IamException, "a_policy"):
            AwsIamClient(mock_boto_iam).create_policy("a_policy", {})

    def test_attach_role_policy(self) -> None:
        a_role, a_policy = role(name="some_role", policies=[]), policy(arn="some_policy_arn")
        updated_role = role(name="some_role", policies=[a_policy])
        mock_boto_iam = Mock()
        with patch.object(AwsIamClient, "get_role", side_effect=lambda n: updated_role if n == "some_role" else None):
            self.assertEqual(updated_role, AwsIamClient(mock_boto_iam).attach_role_policy(a_role, a_policy))
        mock_boto_iam.attach_role_policy.assert_called_once_with(RoleName="some_role", PolicyArn="some_policy_arn")

    def test_attach_role_policy_failure(self) -> None:
        mock_iam = Mock(attach_role_policy=Mock(side_effect=client_error("AttachRolePolicy", "NoSuchEntity", "no")))
        with self.assertRaisesRegex(IamException, "unable to attach role a_role and policy a_policy_arn"):
            AwsIamClient(mock_iam).attach_role_policy(role(name="a_role"), policy(arn="a_policy_arn"))
