from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, patch

from contextlib import redirect_stderr
from io import StringIO

from src.clients.aws_kms_client import AwsKmsClient
from src.data.aws_scanner_exceptions import KmsException

from tests.clients.test_aws_kms_responses import DESCRIBE_KEY, GET_KEY_POLICY
from tests.test_types_generator import client_error, key


class TestAwsIamClient(AwsScannerTestCase):
    def test_find_key(self) -> None:
        key_id = "1234"
        a_key, a_policy = key(id=key_id), {"something": "some value"}
        with patch.object(AwsKmsClient, "_describe_key", side_effect=lambda k: a_key if k == key_id else None):
            with patch.object(AwsKmsClient, "_get_key_policy", side_effect=lambda k: a_policy if k == key_id else None):
                self.assertEqual(key(id=key_id, policy=a_policy), AwsKmsClient(Mock()).find_key(key_id))

    def test_find_key_not_found(self) -> None:
        with patch.object(AwsKmsClient, "_describe_key", side_effect=KmsException("key not found")):
            with redirect_stderr(StringIO()) as err:
                self.assertIsNone(AwsKmsClient(Mock()).find_key("does-not-exist"))
        self.assertIn("does-not-exist", err.getvalue())
        self.assertIn("key not found", err.getvalue())

    def test_describe_key(self) -> None:
        boto_kms = Mock(describe_key=Mock(return_value=DESCRIBE_KEY))
        self.assertEqual(key(), AwsKmsClient(boto_kms)._describe_key("1234abcd"))
        boto_kms.describe_key.assert_called_with(KeyId="1234abcd")

    def test_describe_key_failure(self) -> None:
        boto_kms = Mock(describe_key=Mock(side_effect=client_error("DescribeKey", "NotFoundException", "nope")))
        with self.assertRaisesRegex(KmsException, "ghost-key"):
            AwsKmsClient(boto_kms)._describe_key("ghost-key")

    def test_get_key_policy(self) -> None:
        boto_kms = Mock(get_key_policy=Mock(return_value=GET_KEY_POLICY))
        self.assertEqual({"Statement": [{"Effect": "Allow"}]}, AwsKmsClient(boto_kms)._get_key_policy("1234abcd"))
        boto_kms.get_key_policy.assert_called_with(KeyId="1234abcd")

    def test_get_key_policy_failure(self) -> None:
        boto_kms = Mock(get_key_policy=Mock(side_effect=client_error("GetKeyPolicy", "NotFoundException", "no")))
        with self.assertRaisesRegex(KmsException, "ghost-key"):
            AwsKmsClient(boto_kms)._get_key_policy("ghost-key")
