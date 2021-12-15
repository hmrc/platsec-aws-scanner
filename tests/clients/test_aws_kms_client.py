from unittest import TestCase
from unittest.mock import Mock, patch

from src.clients.aws_kms_client import AwsKmsClient
from src.data.aws_common_types import Tag
from src.data.aws_scanner_exceptions import KmsException

from tests import test_types_generator as generator

from tests.clients.test_aws_kms_responses import (
    DESCRIBE_KEY,
    GET_KEY_POLICY,
    LIST_RESOURCE_TAGS,
)
from tests.test_types_generator import client_error, key


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

    def test_find_key(self) -> None:
        key_id = "1234"
        a_key = key(id=key_id)
        with patch.object(AwsKmsClient, "get_key", side_effect=lambda k: a_key if k == key_id else None):
            self.assertEqual(a_key, AwsKmsClient(Mock()).find_key("1234"))

    def test_find_key_not_found(self) -> None:
        with patch.object(AwsKmsClient, "get_key", side_effect=KmsException("boom")):
            with self.assertLogs("AwsKmsClient", level="WARNING") as warn_log:
                self.assertIsNone(AwsKmsClient(Mock()).find_key("1234"))
                self.assertIn("boom", warn_log.output[0])

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
