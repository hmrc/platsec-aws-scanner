from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from contextlib import redirect_stderr
from io import StringIO
from typing import Any, Dict

from src.clients.aws_s3_client import AwsS3Client

from tests import _raise
from tests.clients import test_aws_s3_client_responses as responses
from tests.test_types_generator import bucket, bucket_encryption, bucket_logging, bucket_secure_transport, client_error


class TestAwsS3ClientListBuckets(AwsScannerTestCase):
    def test_list_buckets(self) -> None:
        client = AwsS3Client(Mock(list_buckets=Mock(return_value=responses.LIST_BUCKETS)))
        expected_buckets = [bucket("a-bucket"), bucket("another-bucket")]
        self.assertEqual(expected_buckets, client.list_buckets())


class TestAwsS3ClientGetBucketEncryption(AwsScannerTestCase):
    @staticmethod
    def get_bucket_encryption(**kwargs) -> Dict[Any, Any]:
        return {
            "cmk-bucket": lambda: responses.GET_BUCKET_ENCRYPTION_CMK,
            "managed-bucket": lambda: responses.GET_BUCKET_ENCRYPTION_AWS_MANAGED,
            "aes-bucket": lambda: responses.GET_BUCKET_ENCRYPTION_AES,
            "keyless-bucket": lambda: responses.GET_BUCKET_ENCRYPTION_KEYLESS,
            "bad-bucket": lambda: _raise(
                client_error(
                    "GetBucketEncryption",
                    "ServerSideEncryptionConfigurationNotFoundError",
                    "The server side encryption configuration was not found",
                )
            ),
        }.get(kwargs.get("Bucket"))()

    def s3_client(self) -> AwsS3Client:
        return AwsS3Client(Mock(get_bucket_encryption=Mock(side_effect=self.get_bucket_encryption)))

    def test_get_bucket_encryption_cmk(self) -> None:
        encryption = bucket_encryption(enabled=True, type="cmk")
        self.assertEqual(encryption, self.s3_client().get_bucket_encryption("cmk-bucket"))

    def test_get_bucket_encryption_aws_managed(self) -> None:
        encryption = bucket_encryption(enabled=True, type="aws")
        self.assertEqual(encryption, self.s3_client().get_bucket_encryption("managed-bucket"))

    def test_get_bucket_encryption_aes(self) -> None:
        encryption = bucket_encryption(enabled=True, type="aes")
        self.assertEqual(encryption, self.s3_client().get_bucket_encryption("aes-bucket"))

    def test_get_bucket_encryption_keyless(self) -> None:
        encryption = bucket_encryption(enabled=True, type="aws")
        self.assertEqual(encryption, self.s3_client().get_bucket_encryption("keyless-bucket"))

    def test_get_bucket_encryption_not_encrypted(self) -> None:
        with redirect_stderr(StringIO()) as err:
            self.assertEqual(bucket_encryption(enabled=False), self.s3_client().get_bucket_encryption("bad-bucket"))
        self.assertIn("ServerSideEncryptionConfigurationNotFoundError", err.getvalue())


class TestAwsS3ClientGetBucketLogging(AwsScannerTestCase):
    @staticmethod
    def get_bucket_logging(**kwargs) -> Dict[Any, Any]:
        return {
            "logging-enabled-bucket": lambda: responses.GET_BUCKET_LOGGING_ENABLED,
            "logging-disabled-bucket": lambda: responses.GET_BUCKET_LOGGING_DISABLED,
            "denied-bucket": lambda: _raise(client_error("GetBucketLogging", "AccessDenied", "Access Denied")),
        }.get(kwargs.get("Bucket"))()

    def s3_client(self) -> AwsS3Client:
        return AwsS3Client(Mock(get_bucket_logging=Mock(side_effect=self.get_bucket_logging)))

    def test_get_bucket_logging_enabled(self) -> None:
        logging = bucket_logging(enabled=True)
        self.assertEqual(logging, self.s3_client().get_bucket_logging("logging-enabled-bucket"))

    def test_get_bucket_logging_disabled(self) -> None:
        logging = bucket_logging(enabled=False)
        self.assertEqual(logging, self.s3_client().get_bucket_logging("logging-disabled-bucket"))

    def test_get_bucket_logging_failure(self) -> None:
        with redirect_stderr(StringIO()) as err:
            self.assertEqual(bucket_logging(enabled=False), self.s3_client().get_bucket_logging("denied-bucket"))
        self.assertIn("AccessDenied", err.getvalue())


class TestAwsS3ClientGetBucketSecureTransport(AwsScannerTestCase):
    @staticmethod
    def get_bucket_policy(**kwargs) -> Dict[Any, Any]:
        return {
            "bucket": lambda: responses.GET_BUCKET_POLICY,
            "secure-bucket": lambda: responses.GET_BUCKET_POLICY_SECURE_TRANSPORT,
            "denied": lambda: _raise(client_error("GetBucketPolicy", "AccessDenied", "Access Denied")),
        }.get(kwargs.get("Bucket"))()

    def s3_client(self) -> AwsS3Client:
        return AwsS3Client(Mock(get_bucket_policy=Mock(side_effect=self.get_bucket_policy)))

    def test_get_bucket_secure_transport_disabled(self) -> None:
        secure_transport = bucket_secure_transport(enabled=False)
        self.assertEqual(secure_transport, self.s3_client().get_bucket_secure_transport("bucket"))

    def test_get_bucket_secure_transport_enabled(self) -> None:
        secure_transport = bucket_secure_transport(enabled=True)
        self.assertEqual(secure_transport, self.s3_client().get_bucket_secure_transport("secure-bucket"))

    def test_get_bucket_secure_transport_failure(self) -> None:
        secure_transport = bucket_secure_transport(enabled=False)
        with redirect_stderr(StringIO()) as err:
            self.assertEqual(secure_transport, self.s3_client().get_bucket_secure_transport("denied"))
        self.assertIn("AccessDenied", err.getvalue())
