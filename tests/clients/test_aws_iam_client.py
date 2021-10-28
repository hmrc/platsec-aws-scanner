from typing import Dict, Optional, Any
from unittest.mock import Mock, patch, call

from unittest import TestCase
from src.clients.aws_iam_client import AwsIamClient
from src.data.aws_scanner_exceptions import IamException

from tests.clients import test_aws_iam_client_responses as resp
from tests.test_types_generator import client_error, role, policy, tag


class TestAwsIamClient(TestCase):
    @staticmethod
    def get_role(**kwargs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return resp.GET_ROLE if str(kwargs["RoleName"]) == "a_role" else None

    @staticmethod
    def list_attached_role_policies_paginator() -> Mock:
        return Mock(
            paginate=Mock(
                side_effect=lambda **k: iter(resp.LIST_ATTACHED_ROLE_POLICIES_PAGES)
                if k["RoleName"] == "a_role"
                else None
            )
        )

    @staticmethod
    def list_policies() -> Mock:
        return Mock(
            paginate=Mock(side_effect=lambda **k: iter(resp.LIST_POLICIES_PAGES) if k["Scope"] == "All" else None)
        )

    @staticmethod
    def get_policy(**kwargs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return resp.GET_POLICY if str(kwargs["PolicyArn"]) == "arn:aws:iam::112233445566:policy/a_policy" else None

    @staticmethod
    def get_policy_version(**kwargs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return (
            resp.GET_POLICY_VERSION
            if str(kwargs["PolicyArn"]) == "arn:aws:iam::112233445566:policy/a_policy"
            and str(kwargs["VersionId"]) == "v3"
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
        self.assertEqual(resp.EXPECTED_ROLE, AwsIamClient(mock_boto_iam).get_role("a_role"))

    def test_find_role_by_arn(self) -> None:
        client = AwsIamClient(Mock())
        with patch.object(AwsIamClient, "find_role") as get_role:
            client.find_role_by_arn("arn:aws:iam::account:role/some_role")
            client.find_role_by_arn("arn:aws:iam:region:account:role/with/path")
            client.find_role_by_arn("not_an_arn_works_too")
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

    def test_get_policy_arn_not_found(self) -> None:
        mock_iam = Mock(
            get_paginator=Mock(side_effect=lambda op: self.list_policies() if op == "list_policies" else None)
        )
        self.assertIsNone(AwsIamClient(mock_iam).find_policy_arn("pol_6"))

    def test_get_policy_arn_failure(self) -> None:
        mock_iam = Mock(get_paginator=Mock(side_effect=client_error("GetPaginator", "OpNotSupported", "boom")))
        with self.assertRaisesRegex(IamException, "boom"):
            AwsIamClient(mock_iam).find_policy_arn("some_policy")

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
        self.assertEqual(role(name=name, arn=arn, assume_policy=assume_policy, policies=[], tags=[]), created)
        mock_boto_iam.create_role.assert_called_once_with(RoleName=name, AssumeRolePolicyDocument='{"key": "val"}')

    def test_create_role_failure(self) -> None:
        mock_boto_iam = Mock(create_role=Mock(side_effect=client_error("CreateRole", "EntityAlreadyExists", "failed")))
        with self.assertRaisesRegex(IamException, "a_role"):
            AwsIamClient(mock_boto_iam).create_role("a_role", {})

    def test_attach_role_policy(self) -> None:
        a_role, a_policy_arn = role(name="some_role", policies=[]), "some_policy_arn"
        updated_role = role(name="some_role", policies=[policy(arn=a_policy_arn)])
        mock_boto_iam = Mock()
        with patch.object(AwsIamClient, "get_role", side_effect=lambda n: updated_role if n == "some_role" else None):
            self.assertEqual(updated_role, AwsIamClient(mock_boto_iam).attach_role_policy(a_role, a_policy_arn))
        mock_boto_iam.attach_role_policy.assert_called_once_with(RoleName="some_role", PolicyArn="some_policy_arn")

    def test_attach_role_policy_failure(self) -> None:
        mock_iam = Mock(attach_role_policy=Mock(side_effect=client_error("AttachRolePolicy", "NoSuchEntity", "no")))
        with self.assertRaisesRegex(IamException, "unable to attach role a_role and policy a_policy_arn"):
            AwsIamClient(mock_iam).attach_role_policy(role(name="a_role"), "a_policy_arn")

    def test_delete_role(self) -> None:
        a_role = role(name="some_role", policies=[policy(arn="pol_1_arn"), policy(arn="pol_2_arn")])
        boto_iam = Mock()
        with patch.object(AwsIamClient, "get_role", side_effect=lambda r: a_role if r == "some_role" else None):
            AwsIamClient(boto_iam).delete_role("some_role")
        self.assertEqual(
            [
                call.detach_role_policy(RoleName="some_role", PolicyArn="pol_1_arn"),
                call.detach_role_policy(RoleName="some_role", PolicyArn="pol_2_arn"),
                call.delete_role(RoleName="some_role"),
            ],
            boto_iam.mock_calls,
        )

    def test_delete_role_that_does_not_exist(self) -> None:
        boto_iam = Mock()
        with patch.object(AwsIamClient, "find_role", return_value=None):
            AwsIamClient(boto_iam).delete_role("ghost_role")
        self.assertFalse(boto_iam.mock_calls)

    def test_delete_role_failure(self) -> None:
        mock_iam = Mock(delete_role=Mock(side_effect=client_error("DeleteRole", "DeleteConflictException", "nope")))
        with patch.object(AwsIamClient, "get_role"):
            with self.assertRaisesRegex(IamException, "unable to delete role broken_role: An error occurred"):
                AwsIamClient(mock_iam).delete_role("broken_role")

    def test_list_entities_for_policy_failure(self) -> None:
        mock_iam = Mock(list_entities_for_policy=Mock(side_effect=client_error("ListEntitiesForPolicy", "Boom", "no")))
        with self.assertRaisesRegex(IamException, "unable to list entities for policy a_policy"):
            AwsIamClient(mock_iam)._list_entities_for_policy("a_policy")

    def test_detach_role_policy_failure(self) -> None:
        mock_iam = Mock(detach_role_policy=Mock(side_effect=client_error("ListEntitiesForPolicy", "Boom", "no")))
        with self.assertRaisesRegex(IamException, "unable to detach role some_role from policy some_policy_arn"):
            AwsIamClient(mock_iam)._detach_role_policy("some_role", "some_policy_arn")

    def test_list_policy_versions_failure(self) -> None:
        mock_iam = Mock(list_policy_versions=Mock(side_effect=client_error("ListEntitiesForPolicy", "Boom", "no")))
        with self.assertRaisesRegex(IamException, "unable to list policy versions for policy some_policy_arn"):
            AwsIamClient(mock_iam)._list_policy_versions("some_policy_arn")

    def test_tag_role(self) -> None:
        mock_iam = Mock()
        AwsIamClient(mock_iam).tag_role("some_role", [tag("a_key", "a value"), tag("some_key", "some value")])
        mock_iam.tag_role.assert_called_once_with(
            RoleName="some_role",
            Tags=[{"Key": "a_key", "Value": "a value"}, {"Key": "some_key", "Value": "some value"}],
        )

    def test_tag_role_failure(self) -> None:
        mock_iam = Mock(tag_role=Mock(side_effect=client_error("TagRole", "AccessDenied", "nope!")))
        with self.assertRaisesRegex(IamException, "unable to tag role a_role"):
            AwsIamClient(mock_iam).tag_role("a_role", [tag("k", "v")])
