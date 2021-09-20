from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, patch

from src.clients.aws_kms_client import AwsKmsClient
from src.data.aws_scanner_exceptions import KmsException

from tests.clients.test_aws_kms_responses import (
    CREATE_KEY,
    DESCRIBE_KEY,
    GET_KEY_POLICY,
    LIST_ALIASES_PAGES,
)
from tests.test_types_generator import alias, client_error, key


class TestAwsKmsClient(AwsScannerTestCase):
    def test_get_key(self) -> None:
        key_id = "1234"
        a_key, a_policy = key(id=key_id), {"something": "some value"}
        with patch.object(AwsKmsClient, "_describe_key", side_effect=lambda k: a_key if k == key_id else None):
            with patch.object(AwsKmsClient, "_get_key_policy", side_effect=lambda k: a_policy if k == key_id else None):
                self.assertEqual(key(id=key_id, policy=a_policy), AwsKmsClient(Mock()).get_key(key_id))

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
        policy_statements = [{"a": 1}, {"b": 2}]
        boto_kms = Mock(create_key=Mock(return_value=CREATE_KEY), create_alias=Mock(return_value=None))
        with patch.object(AwsKmsClient, "_put_key_policy_statements") as put_key_policy:
            self.assertIsNone(AwsKmsClient(boto_kms).create_key("brand-new-alias", "brand new key", policy_statements))
        boto_kms.create_key.assert_called_with(Description="brand new key")
        boto_kms.create_alias.assert_called_with(TargetKeyId="5678ffff", AliasName="alias/brand-new-alias")
        put_key_policy.assert_called_once_with("5678ffff", policy_statements)

    def test_create_key_failure(self) -> None:
        boto_kms = Mock(create_key=Mock(side_effect=client_error("CreateKey", "AccessDeniedException", "nope!")))
        with self.assertRaisesRegex(KmsException, "some_description"):
            AwsKmsClient(boto_kms).create_key("some_alias", "some_description", [])

    def test_create_alias_failure(self) -> None:
        boto_kms = Mock(create_alias=Mock(side_effect=client_error("CreateAlias", "AccessDeniedException", "no!!!")))
        with self.assertRaisesRegex(KmsException, "unable to create alias 'some_alias' for key 'some_key': An error"):
            AwsKmsClient(boto_kms)._create_alias("some_key", "some_alias")

    def test_put_key_policy_statements(self) -> None:
        boto_kms = Mock(put_key_policy=Mock(return_value=None))
        policy = {"Statement": [{"a": 1}]}
        with patch.object(AwsKmsClient, "_get_key_policy", side_effect=lambda k: policy if k == "1234" else None):
            AwsKmsClient(boto_kms)._put_key_policy_statements("1234", [{"b": 2}, {"c": 3}])
        boto_kms.put_key_policy.assert_called_once_with(
            KeyId="1234", PolicyName="default", Policy='{"Statement": [{"a": 1}, {"b": 2}, {"c": 3}]}'
        )

    def test_put_key_policy_statements_failure(self) -> None:
        boto_kms = Mock(
            get_key_policy=Mock(return_value=GET_KEY_POLICY),
            put_key_policy=Mock(side_effect=client_error("PutKeyPolicy", "AccessDeniedException", "no!")),
        )
        with self.assertRaisesRegex(KmsException, "some_key"):
            AwsKmsClient(boto_kms)._put_key_policy_statements("some_key", [{}])

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

    def test_list_aliases_failure(self) -> None:
        kms = Mock(get_paginator=Mock(side_effect=client_error("ListAliases", "AccessDeniedException", "nope!")))
        with self.assertRaisesRegex(KmsException, "unable to list kms key aliases: An error occurred"):
            AwsKmsClient(kms)._list_aliases()
