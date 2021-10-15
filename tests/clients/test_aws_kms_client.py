from unittest import TestCase
from unittest.mock import Mock, patch

from src.clients.aws_kms_client import AwsKmsClient
from src.data.aws_common_types import Tag
from src.data.aws_kms_types import to_key
from src.data.aws_scanner_exceptions import KmsException

from tests import test_types_generator as generator

from tests.clients.test_aws_kms_responses import (
    CREATE_KEY,
    DESCRIBE_KEY,
    GET_KEY_POLICY,
    LIST_ALIASES_PAGES,
    LIST_RESOURCE_TAGS,
)
from tests.test_types_generator import alias, client_error, key


class TestAwsKmsClient(TestCase):
    def test_get_key(self) -> None:
        key_id = "1234"
        a_key, a_policy = key(id=key_id), {"something": "some value"}
        with patch.object(AwsKmsClient, "_describe_key", side_effect=lambda k: a_key if k == key_id else None):
            with patch.object(AwsKmsClient, "_get_key_policy", side_effect=lambda k: a_policy if k == key_id else None):
                with patch.object(
                    AwsKmsClient, "_list_resource_tags", side_effect=lambda k: a_key.tags if k == key_id else None
                ) as list_resource_tags:
                    self.assertEqual(
                        key(id=key_id, policy=a_policy, tags=key().tags), AwsKmsClient(Mock()).get_key(key_id)
                    )

        list_resource_tags.assert_called_once_with(key_id)

    def test_describe_key(self) -> None:
        boto_kms = Mock(describe_key=Mock(return_value=DESCRIBE_KEY))
        self.assertEqual(key(policy=None), AwsKmsClient(boto_kms)._describe_key("1234abcd"))
        boto_kms.describe_key.assert_called_with(KeyId="1234abcd")

    def test_describe_key_failure(self) -> None:
        boto_kms = Mock(describe_key=Mock(side_effect=client_error("DescribeKey", "NotFoundException", "nope")))
        with self.assertRaisesRegex(KmsException, "ghost-key"):
            AwsKmsClient(boto_kms)._describe_key("ghost-key")

    def test_get_key_policy(self) -> None:
        boto_kms = Mock(get_key_policy=Mock(return_value=GET_KEY_POLICY))
        self.assertEqual({"Statement": [{"Effect": "Allow"}]}, AwsKmsClient(boto_kms)._get_key_policy("1234abcd"))
        boto_kms.get_key_policy.assert_called_with(KeyId="1234abcd", PolicyName="default")

    def test_get_key_policy_failure(self) -> None:
        boto_kms = Mock(get_key_policy=Mock(side_effect=client_error("GetKeyPolicy", "NotFoundException", "no")))
        with self.assertRaisesRegex(KmsException, "ghost-key"):
            AwsKmsClient(boto_kms)._get_key_policy("ghost-key")

    def test_create_key(self) -> None:
        boto_kms = Mock(create_key=Mock(return_value=CREATE_KEY), create_alias=Mock(return_value=None))
        actual_key = AwsKmsClient(boto_kms).create_key("brand-new-alias", "brand new key")
        expected_key = to_key(CREATE_KEY["KeyMetadata"])
        self.assertEqual(expected_key, actual_key)

        boto_kms.create_key.assert_called_with(
            Description="brand new key",
            Tags=[
                {"TagKey": "allow-management-by-platsec-scanner", "TagValue": "true"},
                {"TagKey": "src-repo", "TagValue": "https://github.com/hmrc/platsec-aws-scanner"},
            ],
        )
        boto_kms.create_alias.assert_called_with(TargetKeyId="5678ffff", AliasName="alias/brand-new-alias")

    def test_create_key_failure(self) -> None:
        boto_kms = Mock(create_key=Mock(side_effect=client_error("CreateKey", "AccessDeniedException", "nope!")))
        with self.assertRaisesRegex(KmsException, "some_description"):
            AwsKmsClient(boto_kms).create_key("some_alias", "some_description")

    def test_put_key_policy(self) -> None:
        boto_kms = Mock(put_key_policy=Mock())
        expected_policy = '{"Version": "2008-10-17", "Statement": [{"first": "foo"}, {"second": "bar"}]}'
        expected_key = key()

        policy_statements = [{"first": "foo"}, {"second": "bar"}]
        AwsKmsClient(boto_kms).put_key_policy_statements(expected_key.id, policy_statements)
        boto_kms.put_key_policy.assert_called_once_with(
            KeyId=expected_key.id, PolicyName="default", Policy=(expected_policy)
        )

    def test_create_alias_failure(self) -> None:
        boto_kms = Mock(create_alias=Mock(side_effect=client_error("CreateAlias", "AccessDeniedException", "no!!!")))
        with self.assertRaisesRegex(KmsException, "unable to create alias 'some_alias' for key 'some_key': An error"):
            AwsKmsClient(boto_kms)._create_alias("some_key", "some_alias")

    def test_put_key_policy_statements_failure(self) -> None:
        boto_kms = Mock(
            get_key_policy=Mock(return_value=GET_KEY_POLICY),
            put_key_policy=Mock(side_effect=client_error("PutKeyPolicy", "AccessDeniedException", "no!")),
        )
        with self.assertRaisesRegex(KmsException, "some_key"):
            AwsKmsClient(boto_kms).put_key_policy_statements("some_key", [{}])

    @staticmethod
    def list_aliases() -> Mock:
        return Mock(paginate=Mock(side_effect=lambda: iter(LIST_ALIASES_PAGES)))

    def test_find_alias(self) -> None:
        kms = Mock(get_paginator=Mock(side_effect=lambda op: self.list_aliases() if op == "list_aliases" else None))
        client = AwsKmsClient(kms)
        self.assertIsNone(client.find_alias("not-a-alias"))
        self.assertEqual(
            alias(name="alias/alias-2", arn="arn:aws:kms:us-east-1:111222333444:alias/alias-2", target_key_id=None),
            client.find_alias("alias-2"),
        )

    def test_get_alias(self) -> None:
        kms = Mock(get_paginator=Mock(side_effect=lambda op: self.list_aliases() if op == "list_aliases" else None))
        client = AwsKmsClient(kms)
        self.assertEqual(
            alias(name="alias/alias-2", arn="arn:aws:kms:us-east-1:111222333444:alias/alias-2", target_key_id=None),
            client.get_alias("alias-2"),
        )

    def test_get_alias_not_found(self) -> None:
        kms = Mock(get_paginator=Mock(side_effect=lambda op: self.list_aliases() if op == "list_aliases" else None))
        with self.assertRaisesRegex(KmsException, "not-an-alias"):
            AwsKmsClient(kms).get_alias("not-an-alias")

    def test_list_aliases_failure(self) -> None:
        kms = Mock(get_paginator=Mock(side_effect=client_error("ListAliases", "AccessDeniedException", "nope!")))
        with self.assertRaisesRegex(KmsException, "unable to list kms key aliases: An error occurred"):
            AwsKmsClient(kms)._list_aliases()

    def test_delete_alias(self) -> None:
        boto_kms = Mock(delete_alias=Mock(return_value=None))

        AwsKmsClient(boto_kms).delete_alias(name="testName")

        boto_kms.delete_alias.assert_called_with(AliasName="alias/testName")

    def test_delete_alias_failure(self) -> None:
        boto_kms = Mock(delete_alias=Mock(side_effect=client_error("DeleteAlias", "AccessDeniedException", "nope!")))

        with self.assertRaisesRegex(
            expected_exception=KmsException,
            expected_regex="unable to delete kms key alias named 'alias/testName': An error occurred",
        ):
            AwsKmsClient(boto_kms).delete_alias(name="testName")

        boto_kms.delete_alias.assert_called_with(AliasName="alias/testName")

    def test_list_resource_tags(self) -> None:
        key = generator.key()
        expected_response = [Tag(key="tag1", value="value1"), Tag(key="tag2", value="value2")]
        boto_kms = Mock(list_resource_tags=Mock(return_value=LIST_RESOURCE_TAGS))

        response = AwsKmsClient(boto_kms)._list_resource_tags(key_id=key.id)

        boto_kms.list_resource_tags.assert_called_with(KeyId=key.id)
        self.assertEqual(expected_response, response)

    def test_list_resource_tags_failure(self) -> None:
        key = generator.key()
        boto_kms = Mock(
            list_resource_tags=Mock(side_effect=client_error("ListResourceTags", "AccessDeniedException", "nope!"))
        )

        with self.assertRaisesRegex(
            expected_exception=KmsException,
            expected_regex=f"unable to list tags for kms key '{key.id}': An error occurred",
        ):
            AwsKmsClient(boto_kms)._list_resource_tags(key_id=key.id)

        boto_kms.list_resource_tags.assert_called_with(KeyId=key.id)
