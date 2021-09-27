from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from contextlib import redirect_stderr
from io import StringIO
from typing import Any, Dict, Sequence

from src.clients.aws_s3_client import AwsS3Client

from tests import _raise
from tests.clients import test_aws_s3_client_responses as responses
from tests.test_types_generator import (
    bucket,
    bucket_acl,
    bucket_content_deny,
    bucket_cors,
    bucket_data_tagging,
    bucket_encryption,
    bucket_lifecycle,
    bucket_logging,
    bucket_mfa_delete,
    bucket_public_access_block,
    bucket_secure_transport,
    bucket_versioning,
    client_error,
)


class TestAwsS3ClientListBuckets(AwsScannerTestCase):
    def test_list_buckets(self) -> None:
        client = AwsS3Client(Mock(list_buckets=Mock(return_value=responses.LIST_BUCKETS)))
        expected_buckets = [bucket("a-bucket"), bucket("another-bucket")]
        self.assertEqual(expected_buckets, client.list_buckets())


class TestAwsS3ClientGetBucketAccessControlList(AwsScannerTestCase):
    @staticmethod
    def get_bucket_acl(**kwargs: Dict[str, Any]) -> Any:
        bucket = str(kwargs["Bucket"])

        if bucket == "access-denied":
            raise client_error("GetBucketAcl", "AccessDenied", "Access Denied")

        acl: Dict[str, Any] = {
            "no-grant": responses.GET_BUCKET_ACL_NO_GRANT,
            "owner-grant": responses.GET_BUCKET_ACL_OWNER_GRANT,
            "all-users-grant": responses.GET_BUCKET_ACL_ALL_USERS_GRANT,
            "authenticated-users-grant": responses.GET_BUCKET_ACL_AUTHENTICATED_USERS_GRANT,
        }
        return acl[bucket]

    def s3_client(self) -> AwsS3Client:
        return AwsS3Client(Mock(get_bucket_acl=Mock(side_effect=self.get_bucket_acl)))

    def test_get_bucket_acl_no_grant(self) -> None:
        acl = bucket_acl(all_users_enabled=False, authenticated_users_enabled=False)
        self.assertEqual(acl, self.s3_client().get_bucket_acl("no-grant"))

    def test_get_bucket_acl_owner_grant(self) -> None:
        acl = bucket_acl(all_users_enabled=False, authenticated_users_enabled=False)
        self.assertEqual(acl, self.s3_client().get_bucket_acl("owner-grant"))

    def test_get_bucket_acl_all_users_grant(self) -> None:
        acl = bucket_acl(all_users_enabled=True, authenticated_users_enabled=False)
        self.assertEqual(acl, self.s3_client().get_bucket_acl("all-users-grant"))

    def test_get_bucket_acl_authenticated_users_grant(self) -> None:
        acl = bucket_acl(all_users_enabled=False, authenticated_users_enabled=True)
        self.assertEqual(acl, self.s3_client().get_bucket_acl("authenticated-users-grant"))

    def test_get_bucket_acl_failure(self) -> None:
        acl = bucket_acl(all_users_enabled=True, authenticated_users_enabled=True)
        with redirect_stderr(StringIO()) as err:
            self.assertEqual(acl, self.s3_client().get_bucket_acl("access-denied"))
        self.assertIn("AccessDenied", err.getvalue())


class TestAwsS3ClientGetBucketContentDeny(AwsScannerTestCase):
    @staticmethod
    def get_bucket_policy(**kwargs: Dict[str, Any]) -> Any:
        bucket_config = str(kwargs["Bucket"])
        if bucket_config == "access-denied":
            raise client_error("GetBucketPolicy", "AccessDenied", "Access Denied")

        policy_mapping: Dict[str, Any] = {
            "deny-single": responses.GET_BUCKET_POLICY_DENY_GET_PUT_DELETE_SINGLE_STATEMENT,
            "deny-separate": responses.GET_BUCKET_POLICY_DENY_GET_PUT_DELETE_SEPARATE_STATEMENTS,
            "deny-mixed": responses.GET_BUCKET_POLICY_DENY_GET_PUT_DELETE_MIXED_STATEMENTS,
            "deny-incomplete": responses.GET_BUCKET_POLICY_DENY_GET_PUT_SINGLE_STATEMENT,
            "deny-incomplete-separate": responses.GET_BUCKET_POLICY_DENY_GET_DELETE_SEPARATE_STATEMENTS,
            "deny-incomplete-mixed": responses.GET_BUCKET_POLICY_DENY_PUT_DELETE_MIXED_STATEMENTS,
            "allow-mixed": responses.GET_BUCKET_POLICY_ALLOW_GET_PUT_DELETE_MIXED_STATEMENTS,
            "deny-other": responses.GET_BUCKET_POLICY_DENY_OTHER,
        }
        return policy_mapping[bucket_config]

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


class TestAwsS3ClientGetBucketCORS(AwsScannerTestCase):
    @staticmethod
    def get_bucket_cors(**kwargs: Dict[str, Any]) -> Any:
        cors: Dict[Any, Any] = {
            "cors-enabled": lambda: responses.GET_BUCKET_CORS_ENABLED,
            "cors-disabled": lambda: _raise(
                client_error("GetBucketCors", "NoSuchCORSConfiguration", "The CORS configuration does not exist")
            ),
            "access-denied": lambda: _raise(client_error("GetBucketCors", "AccessDenied", "Access Denied")),
        }
        return cors[kwargs["Bucket"]]()

    def s3_client(self) -> AwsS3Client:
        return AwsS3Client(Mock(get_bucket_cors=Mock(side_effect=self.get_bucket_cors)))

    def test_get_bucket_cors_enabled(self) -> None:
        cors = bucket_cors(enabled=True)
        self.assertEqual(cors, self.s3_client().get_bucket_cors("cors-enabled"))

    def test_get_bucket_cors_disabled(self) -> None:
        cors = bucket_cors(enabled=False)
        self.assertEqual(cors, self.s3_client().get_bucket_cors("cors-disabled"))

    def test_get_bucket_cors_failure(self) -> None:
        cors = bucket_cors(enabled=True)
        with redirect_stderr(StringIO()) as err:
            self.assertEqual(cors, self.s3_client().get_bucket_cors("access-denied"))
        self.assertIn("AccessDenied", err.getvalue())


class TestAwsS3ClientGetBucketDataExpiryTagging(AwsScannerTestCase):
    @staticmethod
    def get_bucket_tagging(**kwargs: Dict[str, str]) -> Any:
        expiry_config = str(kwargs["Bucket"])
        if expiry_config == "no-tag":
            raise client_error("GetBucketTagging", "NoSuchTagSet", "The TagSet does not exist")

        expiry: Dict[Any, Any] = {
            "expiry-1-week": responses.GET_BUCKET_TAGGING_EXPIRY_1_WEEK,
            "expiry-1-month": responses.GET_BUCKET_TAGGING_EXPIRY_1_MONTH,
            "expiry-90-days": responses.GET_BUCKET_TAGGING_EXPIRY_90_DAYS,
            "expiry-6-months": responses.GET_BUCKET_TAGGING_EXPIRY_6_MONTHS,
            "expiry-1-year": responses.GET_BUCKET_TAGGING_EXPIRY_1_YEAR,
            "expiry-7-years": responses.GET_BUCKET_TAGGING_EXPIRY_7_YEARS,
            "expiry-10-years": responses.GET_BUCKET_TAGGING_EXPIRY_10_YEARS,
            "expiry-unknown": responses.GET_BUCKET_TAGGING_EXPIRY_UNKNOWN,
            "no-expiry": responses.GET_BUCKET_TAGGING_NO_EXPIRY,
        }
        return expiry[expiry_config]

    def s3_client(self) -> AwsS3Client:
        return AwsS3Client(Mock(get_bucket_tagging=Mock(side_effect=self.get_bucket_tagging)))

    def test_get_bucket_data_tagging_expiry_1_week(self) -> None:
        tagging = bucket_data_tagging(expiry="1-week")
        self.assertEqual(tagging, self.s3_client().get_bucket_data_tagging("expiry-1-week"))

    def test_get_bucket_data_tagging_expiry_1_month(self) -> None:
        tagging = bucket_data_tagging(expiry="1-month")
        self.assertEqual(tagging, self.s3_client().get_bucket_data_tagging("expiry-1-month"))

    def test_get_bucket_data_tagging_expiry_90_days(self) -> None:
        tagging = bucket_data_tagging(expiry="90-days")
        self.assertEqual(tagging, self.s3_client().get_bucket_data_tagging("expiry-90-days"))

    def test_get_bucket_data_tagging_expiry_6_months(self) -> None:
        tagging = bucket_data_tagging(expiry="6-months")
        self.assertEqual(tagging, self.s3_client().get_bucket_data_tagging("expiry-6-months"))

    def test_get_bucket_data_tagging_expiry_1_year(self) -> None:
        tagging = bucket_data_tagging(expiry="1-year")
        self.assertEqual(tagging, self.s3_client().get_bucket_data_tagging("expiry-1-year"))

    def test_get_bucket_data_tagging_expiry_7_years(self) -> None:
        tagging = bucket_data_tagging(expiry="7-years")
        self.assertEqual(tagging, self.s3_client().get_bucket_data_tagging("expiry-7-years"))

    def test_get_bucket_data_tagging_expiry_10_years(self) -> None:
        tagging = bucket_data_tagging(expiry="10-years")
        self.assertEqual(tagging, self.s3_client().get_bucket_data_tagging("expiry-10-years"))

    def test_get_bucket_data_tagging_expiry_unknown(self) -> None:
        tagging = bucket_data_tagging(expiry="unset")
        self.assertEqual(tagging, self.s3_client().get_bucket_data_tagging("expiry-unknown"))

    def test_get_bucket_data_tagging_no_expiry(self) -> None:
        tagging = bucket_data_tagging(expiry="unset")
        self.assertEqual(tagging, self.s3_client().get_bucket_data_tagging("no-expiry"))

    def test_get_bucket_data_tagging_expiry_failure(self) -> None:
        tagging = bucket_data_tagging(expiry="unset")
        with redirect_stderr(StringIO()) as err:
            self.assertEqual(tagging, self.s3_client().get_bucket_data_tagging("no-tag"))
        self.assertIn("NoSuchTagSet", err.getvalue())


class TestAwsS3ClientGetBucketDataSensitivityTagging(AwsScannerTestCase):
    @staticmethod
    def get_bucket_tagging(**kwargs: Dict[str, Any]) -> Any:
        bucket_tag_config: str = str(kwargs["Bucket"])
        if bucket_tag_config == "no-tag":
            raise client_error("GetBucketTagging", "NoSuchTagSet", "The TagSet does not exist")

        tags: Dict[str, Any] = {
            "low-sensitivity": responses.GET_BUCKET_TAGGING_LOW_SENSITIVITY,
            "high-sensitivity": responses.GET_BUCKET_TAGGING_HIGH_SENSITIVITY,
            "unknown-sensitivity": responses.GET_BUCKET_TAGGING_UNKNOWN_SENSITIVITY,
            "no-sensitivity": responses.GET_BUCKET_TAGGING_NO_SENSITIVITY,
        }
        return tags[bucket_tag_config]

    def s3_client(self) -> AwsS3Client:
        return AwsS3Client(Mock(get_bucket_tagging=Mock(side_effect=self.get_bucket_tagging)))

    def test_get_bucket_data_sensitivity_tagging_low(self) -> None:
        tagging = bucket_data_tagging(sensitivity="low")
        self.assertEqual(tagging, self.s3_client().get_bucket_data_tagging("low-sensitivity"))

    def test_get_bucket_data_sensitivity_tagging_high(self) -> None:
        tagging = bucket_data_tagging(sensitivity="high")
        self.assertEqual(tagging, self.s3_client().get_bucket_data_tagging("high-sensitivity"))

    def test_get_bucket_data_sensitivity_tagging_unknown(self) -> None:
        tagging = bucket_data_tagging(sensitivity="unset")
        self.assertEqual(tagging, self.s3_client().get_bucket_data_tagging("unknown-sensitivity"))

    def test_get_bucket_data_sensitivity_no_sensitivity(self) -> None:
        tagging = bucket_data_tagging(sensitivity="unset")
        self.assertEqual(tagging, self.s3_client().get_bucket_data_tagging("no-sensitivity"))

    def test_get_bucket_data_sensitivity_tagging_failure(self) -> None:
        tagging = bucket_data_tagging(sensitivity="unset")
        with redirect_stderr(StringIO()) as err:
            self.assertEqual(tagging, self.s3_client().get_bucket_data_tagging("no-tag"))
        self.assertIn("NoSuchTagSet", err.getvalue())


class TestAwsS3ClientGetBucketEncryption(AwsScannerTestCase):
    @staticmethod
    def get_bucket_encryption(**kwargs: Dict[str, Any]) -> Any:
        bucket = str(kwargs["Bucket"])

        if bucket == "bad-bucket":
            raise client_error(
                "GetBucketEncryption",
                "ServerSideEncryptionConfigurationNotFoundError",
                "The server side encryption configuration was not found",
            )

        encryption_mapping: Dict[str, Any] = {
            "cmk-bucket": responses.GET_BUCKET_ENCRYPTION_CMK,
            "managed-bucket": responses.GET_BUCKET_ENCRYPTION_AWS_MANAGED,
            "aes-bucket": responses.GET_BUCKET_ENCRYPTION_AES,
            "keyless-bucket": responses.GET_BUCKET_ENCRYPTION_KEYLESS,
        }
        return encryption_mapping[bucket]

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
    def get_bucket_logging(**kwargs: Dict[str, Any]) -> Any:
        bucket = str(kwargs["Bucket"])

        if bucket == "denied-bucket":
            raise client_error("GetBucketLogging", "AccessDenied", "Access Denied")

        logging_mapping = {
            "logging-enabled-bucket": responses.GET_BUCKET_LOGGING_ENABLED,
            "logging-disabled-bucket": responses.GET_BUCKET_LOGGING_DISABLED,
        }

        return logging_mapping[bucket]

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


class TestAwsS3ClientGetBucketLifecycle(AwsScannerTestCase):
    @staticmethod
    def get_bucket_lifecycle(**kwargs: Dict[str, Any]) -> Any:
        bucket = str(kwargs["Bucket"])
        if bucket == "no-lifecycle":
            raise client_error(
                "GetBucketLifecycleConfiguration",
                "NoSuchLifecycleConfiguration",
                "The lifecycle configuration does not exist",
            )
        lifecycle_mapping: Dict[str, Any] = {
            "single-rule": responses.GET_BUCKET_LIFECYCLE_CONFIGURATION_SINGLE_RULE,
            "multiple-rules": responses.GET_BUCKET_LIFECYCLE_CONFIGURATION_MULTIPLE_RULES,
            "disabled": responses.GET_BUCKET_LIFECYCLE_CONFIGURATION_DISABLED,
            "no-expiry": responses.GET_BUCKET_LIFECYCLE_CONFIGURATION_NO_EXPIRY,
        }
        return lifecycle_mapping[bucket]

    def s3_client(self) -> AwsS3Client:
        return AwsS3Client(Mock(get_bucket_lifecycle_configuration=Mock(side_effect=self.get_bucket_lifecycle)))

    def test_get_bucket_lifecycle_single_rule(self) -> None:
        lifecycle = bucket_lifecycle(current_version_expiry=15, previous_version_deletion=30)
        self.assertEqual(lifecycle, self.s3_client().get_bucket_lifecycle("single-rule"))

    def test_get_bucket_lifecycle_multiple_rules(self) -> None:
        lifecycle = bucket_lifecycle(current_version_expiry=5, previous_version_deletion=10)
        self.assertEqual(lifecycle, self.s3_client().get_bucket_lifecycle("multiple-rules"))

    def test_get_bucket_lifecycle_disabled(self) -> None:
        lifecycle = bucket_lifecycle(current_version_expiry="unset", previous_version_deletion="unset")
        self.assertEqual(lifecycle, self.s3_client().get_bucket_lifecycle("disabled"))

    def test_get_bucket_lifecycle_no_expiry(self) -> None:
        lifecycle = bucket_lifecycle(current_version_expiry="unset", previous_version_deletion="unset")
        self.assertEqual(lifecycle, self.s3_client().get_bucket_lifecycle("no-expiry"))

    def test_get_bucket_lifecycle_not_set(self) -> None:
        lifecycle = bucket_lifecycle(current_version_expiry="unset", previous_version_deletion="unset")
        with redirect_stderr(StringIO()) as err:
            self.assertEqual(lifecycle, self.s3_client().get_bucket_lifecycle("no-lifecycle"))
        self.assertIn("NoSuchLifecycleConfiguration", err.getvalue())


class TestAwsS3ClientGetBucketMFADelete(AwsScannerTestCase):
    @staticmethod
    def get_bucket_versioning(**kwargs: Dict[str, Any]) -> Any:
        bucket = str(kwargs["Bucket"])
        if bucket == "access-denied":
            raise client_error("GetBucketVersioning", "AccessDenied", "Access Denied")

        versioning_mapping: Dict[str, Any] = {
            "mfa-delete-enabled": responses.GET_BUCKET_VERSIONING_MFA_DELETE_ENABLED,
            "mfa-delete-disabled": responses.GET_BUCKET_VERSIONING_MFA_DELETE_DISABLED,
            "mfa-delete-unset": responses.GET_BUCKET_VERSIONING_MFA_DELETE_UNSET,
        }
        return versioning_mapping[bucket]

    def s3_client(self) -> AwsS3Client:
        return AwsS3Client(Mock(get_bucket_versioning=Mock(side_effect=self.get_bucket_versioning)))

    def test_get_bucket_mfa_delete_enabled(self) -> None:
        mfa_delete = bucket_mfa_delete(enabled=True)
        self.assertEqual(mfa_delete, self.s3_client().get_bucket_mfa_delete("mfa-delete-enabled"))

    def test_get_bucket_mfa_delete_disabled(self) -> None:
        mfa_delete = bucket_mfa_delete(enabled=False)
        self.assertEqual(mfa_delete, self.s3_client().get_bucket_mfa_delete("mfa-delete-disabled"))

    def test_get_bucket_mfa_delete_unset(self) -> None:
        mfa_delete = bucket_mfa_delete(enabled=False)
        self.assertEqual(mfa_delete, self.s3_client().get_bucket_mfa_delete("mfa-delete-unset"))

    def test_get_bucket_mfa_delete_failure(self) -> None:
        mfa_delete = bucket_mfa_delete(enabled=False)
        with redirect_stderr(StringIO()) as err:
            self.assertEqual(mfa_delete, self.s3_client().get_bucket_mfa_delete("access-denied"))
        self.assertIn("AccessDenied", err.getvalue())


class TestAwsS3ClientGetBucketPublicAccessBlock(AwsScannerTestCase):
    @staticmethod
    def s3_client(public_access_block_response: Dict[str, Any]) -> AwsS3Client:
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

        scenarios: Sequence[Dict[str, Any]] = [
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
            self.assertEqual(not_blocked, self.s3_client({}).get_bucket_public_access_block("denied"))
        self.assertIn("AccessDenied", err.getvalue())


class TestAwsS3ClientGetBucketSecureTransport(AwsScannerTestCase):
    @staticmethod
    def get_bucket_policy(**kwargs: Dict[str, Any]) -> Any:
        bucket = str(kwargs["Bucket"])
        if bucket == "denied":
            raise client_error("GetBucketPolicy", "AccessDenied", "Access Denied")

        policy_mapping: Dict[str, Any] = {
            "bucket": responses.GET_BUCKET_POLICY,
            "secure-bucket": responses.GET_BUCKET_POLICY_SECURE_TRANSPORT,
        }
        return policy_mapping[bucket]

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


class TestAwsS3ClientGetBucketVersioning(AwsScannerTestCase):
    @staticmethod
    def get_bucket_versioning(**kwargs: Dict[str, Any]) -> Any:
        bucket = str(kwargs["Bucket"])
        if bucket == "access-denied":
            raise client_error("GetBucketVersioning", "AccessDenied", "Access Denied")

        versioning_mapping: Dict[str, Any] = {
            "versioning-enabled": responses.GET_BUCKET_VERSIONING_ENABLED,
            "versioning-suspended": responses.GET_BUCKET_VERSIONING_SUSPENDED,
            "versioning-unset": responses.GET_BUCKET_VERSIONING_UNSET,
        }
        return versioning_mapping[bucket]

    def s3_client(self) -> AwsS3Client:
        return AwsS3Client(Mock(get_bucket_versioning=Mock(side_effect=self.get_bucket_versioning)))

    def test_get_bucket_versioning_enabled(self) -> None:
        versioning = bucket_versioning(enabled=True)
        self.assertEqual(versioning, self.s3_client().get_bucket_versioning("versioning-enabled"))

    def test_get_bucket_versioning_suspended(self) -> None:
        versioning = bucket_versioning(enabled=False)
        self.assertEqual(versioning, self.s3_client().get_bucket_versioning("versioning-suspended"))

    def test_get_bucket_versioning_unset(self) -> None:
        versioning = bucket_versioning(enabled=False)
        self.assertEqual(versioning, self.s3_client().get_bucket_versioning("versioning-unset"))

    def test_get_bucket_versioning_failure(self) -> None:
        versioning = bucket_versioning(enabled=False)
        with redirect_stderr(StringIO()) as err:
            self.assertEqual(versioning, self.s3_client().get_bucket_versioning("access-denied"))
        self.assertIn("AccessDenied", err.getvalue())


class TestAwsS3ClientPutObject(AwsScannerTestCase):
    @staticmethod
    def put_object(**kwargs: Dict[str, Any]) -> Any:
        bucket = str(kwargs["Bucket"])
        key = str(kwargs["Key"])
        body = str(kwargs["Body"])
        return (
            responses.PUT_OBJECT
            if bucket == "buck" and key == "obj" and body == "bla"
            else _raise(client_error("PutObject", "AccessDenied", "Access Denied"))
        )

    def s3_client(self) -> AwsS3Client:
        return AwsS3Client(Mock(put_object=Mock(side_effect=self.put_object)))

    def test_put_object_success(self) -> None:
        self.assertEqual("some id", self.s3_client().put_object(bucket="buck", object_name="obj", object_content="bla"))

    def test_put_object_failure(self) -> None:
        with redirect_stderr(StringIO()) as err:
            self.s3_client().put_object(bucket="denied", object_name="obj", object_content="bla")
        self.assertIn("AccessDenied", err.getvalue())
