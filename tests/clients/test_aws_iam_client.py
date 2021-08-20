from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

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
from tests.test_types_generator import client_error


class TestAwsIamClient(AwsScannerTestCase):
    @staticmethod
    def get_role(**kwargs) -> Dict[str, Any]:
        return GET_ROLE if kwargs["RoleName"] == "a_role" else None

    @staticmethod
    def list_attached_role_policies(**kwargs) -> Dict[str, Any]:
        return LIST_ATTACHED_ROLE_POLICIES if kwargs["RoleName"] == "a_role" else None

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
            list_attached_role_policies=Mock(side_effect=self.list_attached_role_policies),
            get_policy=Mock(side_effect=self.get_policy),
            get_policy_version=Mock(side_effect=self.get_policy_version),
        )
        self.assertEqual(EXPECTED_ROLE, AwsIamClient(mock_boto_iam).get_role("a_role"))

    def test_get_role_failure(self) -> None:
        mock_boto_iam = Mock(get_role=Mock(side_effect=client_error("GetRole", "NoSuchEntity", "not found")))
        with self.assertRaisesRegex(IamException, "a_role"):
            AwsIamClient(mock_boto_iam).get_role("a_role")

    def test_list_attached_role_policies_failure(self) -> None:
        mock_boto_iam = Mock(
            list_attached_role_policies=Mock(
                side_effect=client_error("ListAttachedRolePolicies", "NoSuchEntity", "not found")
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
