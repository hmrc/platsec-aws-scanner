from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from contextlib import redirect_stderr
from io import StringIO
from typing import Any, Dict, Optional

from src.clients.aws_s3_client import AwsS3Client

from tests import _raise
from tests.clients import test_aws_s3_client_responses as responses
from tests.test_types_generator import (
    bucket,
    bucket_content_deny,
    bucket_data_sensitivity_tagging,
    bucket_encryption,
    bucket_logging,
    bucket_public_access_block,
    bucket_secure_transport,
    client_error,
)


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


class TestAwsS3ClientGetBucketPublicAccessBlock(AwsScannerTestCase):
    @staticmethod
    def s3_client(public_access_block_response: Optional[Dict[Any, Any]] = None) -> AwsS3Client:
        return AwsS3Client(
            Mock(
                get_public_access_block=Mock(
                    side_effect=lambda **kwargs: public_access_block_response
                    if kwargs.get("Bucket") == "bucket"
                    else _raise(client_error("GetPublicAccessBlock", "AccessDenied", "Access Denied")),
                )
            )
        )

    def test_get_bucket_public_access_block(self) -> None:
        blocked = bucket_public_access_block(enabled=True)
        not_blocked = bucket_public_access_block(enabled=False)

        scenarios = [
            {"response": responses.public_access_block(False, False, False, False), "state": not_blocked},
            {"response": responses.public_access_block(False, False, False, True), "state": not_blocked},
            {"response": responses.public_access_block(False, False, True, False), "state": not_blocked},
            {"response": responses.public_access_block(False, True, False, False), "state": not_blocked},
            {"response": responses.public_access_block(True, False, False, False), "state": not_blocked},
            {"response": responses.public_access_block(False, False, True, True), "state": not_blocked},
            {"response": responses.public_access_block(True, True, False, False), "state": not_blocked},
            {"response": responses.public_access_block(False, True, False, True), "state": blocked},
            {"response": responses.public_access_block(True, False, True, False), "state": not_blocked},
            {"response": responses.public_access_block(True, False, False, True), "state": not_blocked},
            {"response": responses.public_access_block(False, True, True, False), "state": not_blocked},
            {"response": responses.public_access_block(False, True, True, True), "state": blocked},
            {"response": responses.public_access_block(True, True, True, False), "state": not_blocked},
            {"response": responses.public_access_block(True, True, False, True), "state": blocked},
            {"response": responses.public_access_block(True, False, True, True), "state": not_blocked},
            {"response": responses.public_access_block(True, True, True, True), "state": blocked},
        ]

        for scenario in scenarios:
            self.assertEqual(
                scenario["state"], self.s3_client(scenario["response"]).get_bucket_public_access_block("bucket")
            )

    def test_get_bucket_public_access_block_failure(self) -> None:
        not_blocked = bucket_public_access_block(enabled=False)
        with redirect_stderr(StringIO()) as err:
            self.assertEqual(not_blocked, self.s3_client().get_bucket_public_access_block("denied"))
        self.assertIn("AccessDenied", err.getvalue())


class TestAwsS3ClientGetBucketDataSensitivityTagging(AwsScannerTestCase):
    @staticmethod
    def get_bucket_tagging(**kwargs) -> Dict[Any, Any]:
        return {
            "low-sensitivity": lambda: responses.GET_BUCKET_TAGGING_LOW_SENSITIVITY,
            "high-sensitivity": lambda: responses.GET_BUCKET_TAGGING_HIGH_SENSITIVITY,
            "unknown-sensitivity": lambda: responses.GET_BUCKET_TAGGING_UNKNOWN_SENSITIVITY,
            "no-sensitivity": lambda: responses.GET_BUCKET_TAGGING_NO_SENSITIVITY,
            "no-tag": lambda: _raise(client_error("GetBucketTagging", "NoSuchTagSet", "The TagSet does not exist")),
        }.get(kwargs.get("Bucket"))()

    def s3_client(self) -> AwsS3Client:
        return AwsS3Client(Mock(get_bucket_tagging=Mock(side_effect=self.get_bucket_tagging)))

    def test_get_bucket_data_sensitivity_tagging_low(self) -> None:
        tagging = bucket_data_sensitivity_tagging(enabled=True)
        self.assertEqual(tagging, self.s3_client().get_bucket_data_sensitivity_tagging("low-sensitivity"))

    def test_get_bucket_data_sensitivity_tagging_high(self) -> None:
        tagging = bucket_data_sensitivity_tagging(enabled=True)
        self.assertEqual(tagging, self.s3_client().get_bucket_data_sensitivity_tagging("high-sensitivity"))

    def test_get_bucket_data_sensitivity_tagging_unknown(self) -> None:
        tagging = bucket_data_sensitivity_tagging(enabled=False)
        self.assertEqual(tagging, self.s3_client().get_bucket_data_sensitivity_tagging("unknown-sensitivity"))

    def test_get_bucket_data_sensitivity_no_sensitivity(self) -> None:
        tagging = bucket_data_sensitivity_tagging(enabled=False)
        self.assertEqual(tagging, self.s3_client().get_bucket_data_sensitivity_tagging("no-sensitivity"))

    def test_get_bucket_data_sensitivity_tagging_failure(self) -> None:
        tagging = bucket_data_sensitivity_tagging(enabled=False)
        with redirect_stderr(StringIO()) as err:
            self.assertEqual(tagging, self.s3_client().get_bucket_data_sensitivity_tagging("no-tag"))
        self.assertIn("NoSuchTagSet", err.getvalue())


class TestAwsS3ClientGetBucketContentDeny(AwsScannerTestCase):
    @staticmethod
    def get_bucket_policy(**kwargs) -> Dict[Any, Any]:
        return {
            "deny-single": lambda: responses.GET_BUCKET_POLICY_DENY_GET_PUT_DELETE_SINGLE_STATEMENT,
            "deny-separate": lambda: responses.GET_BUCKET_POLICY_DENY_GET_PUT_DELETE_SEPARATE_STATEMENTS,
            "deny-mixed": lambda: responses.GET_BUCKET_POLICY_DENY_GET_PUT_DELETE_MIXED_STATEMENTS,
            "deny-incomplete": lambda: responses.GET_BUCKET_POLICY_DENY_GET_PUT_SINGLE_STATEMENT,
            "deny-incomplete-separate": lambda: responses.GET_BUCKET_POLICY_DENY_GET_DELETE_SEPARATE_STATEMENTS,
            "deny-incomplete-mixed": lambda: responses.GET_BUCKET_POLICY_DENY_PUT_DELETE_MIXED_STATEMENTS,
            "allow-mixed": lambda: responses.GET_BUCKET_POLICY_ALLOW_GET_PUT_DELETE_MIXED_STATEMENTS,
            "deny-other": lambda: responses.GET_BUCKET_POLICY_DENY_OTHER,
            "access-denied": lambda: _raise(client_error("GetBucketPolicy", "AccessDenied", "Access Denied")),
        }.get(kwargs.get("Bucket"))()

    def s3_client(self) -> AwsS3Client:
        return AwsS3Client(Mock(get_bucket_policy=Mock(side_effect=self.get_bucket_policy)))

    def test_get_bucket_content_deny_single(self) -> None:
        content_deny = bucket_content_deny(enabled=True)
        self.assertEqual(content_deny, self.s3_client().get_bucket_content_deny("deny-single"))

    def test_get_bucket_content_deny_separate(self) -> None:
        content_deny = bucket_content_deny(enabled=True)
        self.assertEqual(content_deny, self.s3_client().get_bucket_content_deny("deny-separate"))

    def test_get_bucket_content_deny_mixed(self) -> None:
        content_deny = bucket_content_deny(enabled=True)
        self.assertEqual(content_deny, self.s3_client().get_bucket_content_deny("deny-mixed"))

    def test_get_bucket_content_deny_incomplete(self) -> None:
        content_deny = bucket_content_deny(enabled=False)
        self.assertEqual(content_deny, self.s3_client().get_bucket_content_deny("deny-incomplete"))

    def test_get_bucket_content_deny_incomplete_separate(self) -> None:
        content_deny = bucket_content_deny(enabled=False)
        self.assertEqual(content_deny, self.s3_client().get_bucket_content_deny("deny-incomplete-separate"))

    def test_get_bucket_content_deny_incomplete_mixed(self) -> None:
        content_deny = bucket_content_deny(enabled=False)
        self.assertEqual(content_deny, self.s3_client().get_bucket_content_deny("deny-incomplete-mixed"))

    def test_get_bucket_content_deny_allow_mixed(self) -> None:
        content_deny = bucket_content_deny(enabled=False)
        self.assertEqual(content_deny, self.s3_client().get_bucket_content_deny("allow-mixed"))

    def test_get_bucket_content_deny_other(self) -> None:
        content_deny = bucket_content_deny(enabled=False)
        self.assertEqual(content_deny, self.s3_client().get_bucket_content_deny("deny-other"))

    def test_get_bucket_content_deny_failure(self) -> None:
        content_deny = bucket_content_deny(enabled=False)
        with redirect_stderr(StringIO()) as err:
            self.assertEqual(content_deny, self.s3_client().get_bucket_content_deny("access-denied"))
        self.assertIn("AccessDenied", err.getvalue())
