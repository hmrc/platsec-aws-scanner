import logging

from unittest.mock import Mock

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


def test_list_buckets() -> None:
    client = AwsS3Client(Mock(list_buckets=Mock(return_value=responses.LIST_BUCKETS)))
    expected_buckets = [bucket("a-bucket"), bucket("another-bucket")]
    assert expected_buckets == client.list_buckets()


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


def s3_client_acl() -> AwsS3Client:
    return AwsS3Client(Mock(get_bucket_acl=Mock(side_effect=get_bucket_acl)))


def test_get_bucket_acl_no_grant() -> None:
    acl = bucket_acl(all_users_enabled=False, authenticated_users_enabled=False)
    assert acl == s3_client_acl().get_bucket_acl("no-grant")


def test_get_bucket_acl_owner_grant() -> None:
    acl = bucket_acl(all_users_enabled=False, authenticated_users_enabled=False)
    assert acl == s3_client_acl().get_bucket_acl("owner-grant")


def test_get_bucket_acl_all_users_grant() -> None:
    acl = bucket_acl(all_users_enabled=True, authenticated_users_enabled=False)
    assert acl == s3_client_acl().get_bucket_acl("all-users-grant")


def test_get_bucket_acl_authenticated_users_grant() -> None:
    acl = bucket_acl(all_users_enabled=False, authenticated_users_enabled=True)
    assert acl == s3_client_acl().get_bucket_acl("authenticated-users-grant")


def test_get_bucket_acl_failure(caplog: Any) -> None:
    acl = bucket_acl(all_users_enabled=True, authenticated_users_enabled=True)
    with caplog.at_level(logging.WARNING):
        assert acl == s3_client_acl().get_bucket_acl("access-denied")
    assert "AccessDenied" in caplog.text


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


def s3_client_bucket_content() -> AwsS3Client:
    return AwsS3Client(Mock(get_bucket_policy=Mock(side_effect=get_bucket_policy)))


def test_get_bucket_content_deny_single() -> None:
    content_deny = bucket_content_deny(enabled=True)
    assert content_deny == s3_client_bucket_content().get_bucket_content_deny("deny-single")


def test_get_bucket_content_deny_separate() -> None:
    content_deny = bucket_content_deny(enabled=True)
    assert content_deny == s3_client_bucket_content().get_bucket_content_deny("deny-separate")


def test_get_bucket_content_deny_mixed() -> None:
    content_deny = bucket_content_deny(enabled=True)
    assert content_deny == s3_client_bucket_content().get_bucket_content_deny("deny-mixed")


def test_get_bucket_content_deny_incomplete() -> None:
    content_deny = bucket_content_deny(enabled=False)
    assert content_deny == s3_client_bucket_content().get_bucket_content_deny("deny-incomplete")


def test_get_bucket_content_deny_incomplete_separate() -> None:
    content_deny = bucket_content_deny(enabled=False)
    assert content_deny == s3_client_bucket_content().get_bucket_content_deny("deny-incomplete-separate")


def test_get_bucket_content_deny_incomplete_mixed() -> None:
    content_deny = bucket_content_deny(enabled=False)
    assert content_deny == s3_client_bucket_content().get_bucket_content_deny("deny-incomplete-mixed")


def test_get_bucket_content_deny_allow_mixed() -> None:
    content_deny = bucket_content_deny(enabled=False)
    assert content_deny == s3_client_bucket_content().get_bucket_content_deny("allow-mixed")


def test_get_bucket_content_deny_other() -> None:
    content_deny = bucket_content_deny(enabled=False)
    assert content_deny == s3_client_bucket_content().get_bucket_content_deny("deny-other")


def test_get_bucket_content_deny_failure(caplog: Any) -> None:
    content_deny = bucket_content_deny(enabled=False)
    with caplog.at_level(logging.WARNING):
        assert content_deny == s3_client_bucket_content().get_bucket_content_deny("access-denied")
    assert "AccessDenied" in caplog.text


def get_bucket_cors(**kwargs: Dict[str, Any]) -> Any:
    cors: Dict[Any, Any] = {
        "cors-enabled": lambda: responses.GET_BUCKET_CORS_ENABLED,
        "cors-disabled": lambda: _raise(
            client_error("GetBucketCors", "NoSuchCORSConfiguration", "The CORS configuration does not exist")
        ),
        "access-denied": lambda: _raise(client_error("GetBucketCors", "AccessDenied", "Access Denied")),
    }
    return cors[kwargs["Bucket"]]()


def s3_client_cors() -> AwsS3Client:
    return AwsS3Client(Mock(get_bucket_cors=Mock(side_effect=get_bucket_cors)))


def test_get_bucket_cors_enabled() -> None:
    cors = bucket_cors(enabled=True)
    assert cors == s3_client_cors().get_bucket_cors("cors-enabled")


def test_get_bucket_cors_disabled() -> None:
    cors = bucket_cors(enabled=False)
    assert cors == s3_client_cors().get_bucket_cors("cors-disabled")


def test_get_bucket_cors_failure(caplog: Any) -> None:
    cors = bucket_cors(enabled=True)
    with caplog.at_level(logging.WARNING):
        assert cors == s3_client_cors().get_bucket_cors("access-denied")
    assert "AccessDenied" in caplog.text


def get_bucket_expiry_tagging(**kwargs: Dict[str, str]) -> Any:
    expiry_config = str(kwargs["Bucket"])
    if expiry_config == "no-tag":
        raise client_error("GetBucketTagging", "NoSuchTagSet", "The TagSet does not exist")

    expiry: Dict[Any, Any] = {
        "expiry-1-week": responses.GET_BUCKET_TAGGING_EXPIRY_1_WEEK,
        "expiry-1-month": responses.GET_BUCKET_TAGGING_EXPIRY_1_MONTH,
        "expiry-90-days": responses.GET_BUCKET_TAGGING_EXPIRY_90_DAYS,
        "expiry-6-months": responses.GET_BUCKET_TAGGING_EXPIRY_6_MONTHS,
        "expiry-18-months": responses.GET_BUCKET_TAGGING_EXPIRY_18_MONTHS,
        "expiry-1-year": responses.GET_BUCKET_TAGGING_EXPIRY_1_YEAR,
        "expiry-7-years": responses.GET_BUCKET_TAGGING_EXPIRY_7_YEARS,
        "expiry-10-years": responses.GET_BUCKET_TAGGING_EXPIRY_10_YEARS,
        "expiry-forever-config-only": responses.GET_BUCKET_TAGGING_EXPIRY_FOREVER_CONFIG_ONLY,
        "expiry-unknown": responses.GET_BUCKET_TAGGING_EXPIRY_UNKNOWN,
        "no-expiry": responses.GET_BUCKET_TAGGING_NO_EXPIRY,
    }
    return expiry[expiry_config]


def s3_client_expiry_tagging() -> AwsS3Client:
    return AwsS3Client(Mock(get_bucket_tagging=Mock(side_effect=get_bucket_expiry_tagging)))


def test_get_bucket_data_tagging_expiry_1_week() -> None:
    tagging = bucket_data_tagging(expiry="1-week", sensitivity="low")
    assert tagging == s3_client_expiry_tagging().get_bucket_data_tagging("expiry-1-week")


def test_get_bucket_data_tagging_expiry_1_month() -> None:
    tagging = bucket_data_tagging(expiry="1-month", sensitivity="low")
    assert tagging == s3_client_expiry_tagging().get_bucket_data_tagging("expiry-1-month")


def test_get_bucket_data_tagging_expiry_90_days() -> None:
    tagging = bucket_data_tagging(expiry="90-days", sensitivity="low")
    assert tagging == s3_client_expiry_tagging().get_bucket_data_tagging("expiry-90-days")


def test_get_bucket_data_tagging_expiry_6_months() -> None:
    tagging = bucket_data_tagging(expiry="6-months", sensitivity="low")
    assert tagging == s3_client_expiry_tagging().get_bucket_data_tagging("expiry-6-months")


def test_get_bucket_data_tagging_expiry_1_year() -> None:
    tagging = bucket_data_tagging(expiry="1-year", sensitivity="low")
    assert tagging == s3_client_expiry_tagging().get_bucket_data_tagging("expiry-1-year")


def test_get_bucket_data_tagging_expiry_7_years() -> None:
    tagging = bucket_data_tagging(expiry="7-years", sensitivity="low")
    assert tagging == s3_client_expiry_tagging().get_bucket_data_tagging("expiry-7-years")


def test_get_bucket_data_tagging_expiry_10_years() -> None:
    tagging = bucket_data_tagging(expiry="10-years", sensitivity="low")
    assert tagging == s3_client_expiry_tagging().get_bucket_data_tagging("expiry-10-years")


def test_get_bucket_data_tagging_expiry_forever_config_only() -> None:
    tagging = bucket_data_tagging(expiry="forever-config-only", sensitivity="low")
    assert tagging == s3_client_expiry_tagging().get_bucket_data_tagging("expiry-forever-config-only")


def test_get_bucket_data_tagging_expiry_unknown() -> None:
    tagging = bucket_data_tagging(expiry="unset")
    assert tagging == s3_client_expiry_tagging().get_bucket_data_tagging("expiry-unknown")


def test_get_bucket_data_tagging_no_expiry() -> None:
    tagging = bucket_data_tagging(expiry="unset")
    assert tagging == s3_client_expiry_tagging().get_bucket_data_tagging("no-expiry")


def test_get_bucket_data_tagging_expiry_failure(caplog: Any) -> None:
    tagging = bucket_data_tagging(expiry="unset")
    with caplog.at_level(logging.WARNING):
        assert tagging == s3_client_expiry_tagging().get_bucket_data_tagging("no-tag")
    assert "NoSuchTagSet" in caplog.text


def get_bucket_sensitivity_tagging(**kwargs: Dict[str, Any]) -> Any:
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


def s3_client_sensitivity_tagging() -> AwsS3Client:
    return AwsS3Client(Mock(get_bucket_tagging=Mock(side_effect=get_bucket_sensitivity_tagging)))


def test_get_bucket_data_sensitivity_tagging_low() -> None:
    tagging = bucket_data_tagging(expiry="1-week", sensitivity="low")
    assert tagging == s3_client_sensitivity_tagging().get_bucket_data_tagging("low-sensitivity")


def test_get_bucket_data_sensitivity_tagging_high() -> None:
    tagging = bucket_data_tagging(expiry="1-week", sensitivity="high")
    assert tagging == s3_client_sensitivity_tagging().get_bucket_data_tagging("high-sensitivity")


def test_get_bucket_data_sensitivity_tagging_unknown() -> None:
    tagging = bucket_data_tagging(sensitivity="unset")
    assert tagging, s3_client_sensitivity_tagging().get_bucket_data_tagging("unknown-sensitivity")


def test_get_bucket_data_sensitivity_no_sensitivity() -> None:
    tagging = bucket_data_tagging(sensitivity="unset")
    assert tagging == s3_client_sensitivity_tagging().get_bucket_data_tagging("no-sensitivity")


def test_get_bucket_data_sensitivity_tagging_failure(caplog: Any) -> None:
    tagging = bucket_data_tagging(sensitivity="unset")
    with caplog.at_level(logging.WARNING):
        assert tagging == s3_client_sensitivity_tagging().get_bucket_data_tagging("no-tag")
    assert "NoSuchTagSet" in caplog.text


def get_bucket_encryption(**kwargs: Dict[str, Any]) -> Any:
    buck = str(kwargs["Bucket"])

    if buck == "bad-bucket":
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
    return encryption_mapping[buck]


def s3_client_encryption() -> AwsS3Client:
    return AwsS3Client(Mock(get_bucket_encryption=Mock(side_effect=get_bucket_encryption)))


def test_get_bucket_encryption_cmk() -> None:
    encryption = bucket_encryption(enabled=True, key_id="65465465-ab56-423f-ec22-c45623212123", type="cmk")
    assert encryption == s3_client_encryption().get_bucket_encryption("cmk-bucket")


def test_get_bucket_encryption_aws_managed() -> None:
    encryption = bucket_encryption(enabled=True, key_id="arn:aws:kms:some-region:455687898753:alias/aws/s3", type="aws")
    assert encryption == s3_client_encryption().get_bucket_encryption("managed-bucket")


def test_get_bucket_encryption_aes() -> None:
    encryption = bucket_encryption(enabled=True, key_id="", type="aes")
    assert encryption == s3_client_encryption().get_bucket_encryption("aes-bucket")


def test_get_bucket_encryption_keyless() -> None:
    encryption = bucket_encryption(enabled=True, type="aws")
    assert encryption == s3_client_encryption().get_bucket_encryption("keyless-bucket")


def test_get_bucket_encryption_not_encrypted(caplog: Any) -> None:
    with caplog.at_level(logging.WARNING):
        assert bucket_encryption(enabled=False) == s3_client_encryption().get_bucket_encryption("bad-bucket")
        assert "ServerSideEncryptionConfigurationNotFoundError" in caplog.text


def get_bucket_logging(**kwargs: Dict[str, Any]) -> Any:
    buck = str(kwargs["Bucket"])

    if buck == "denied-bucket":
        raise client_error("GetBucketLogging", "AccessDenied", "Access Denied")

    logging_mapping = {
        "logging-enabled-bucket": responses.GET_BUCKET_LOGGING_ENABLED,
        "logging-disabled-bucket": responses.GET_BUCKET_LOGGING_DISABLED,
    }

    return logging_mapping[buck]


def s3_client_logging() -> AwsS3Client:
    return AwsS3Client(Mock(get_bucket_logging=Mock(side_effect=get_bucket_logging)))


def test_get_bucket_logging_enabled() -> None:
    assert bucket_logging(enabled=True) == s3_client_logging().get_bucket_logging("logging-enabled-bucket")


def test_get_bucket_logging_disabled() -> None:
    assert bucket_logging(enabled=False) == s3_client_logging().get_bucket_logging("logging-disabled-bucket")


def test_get_bucket_logging_failure(caplog: Any) -> None:
    with caplog.at_level(logging.WARNING):
        assert bucket_logging(enabled=False) == s3_client_logging().get_bucket_logging("denied-bucket")
        assert "AccessDenied" in caplog.text


def get_bucket_lifecycle(**kwargs: Dict[str, Any]) -> Any:
    buck = str(kwargs["Bucket"])
    if buck == "no-lifecycle":
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
    return lifecycle_mapping[buck]


def s3_client_lifecycle() -> AwsS3Client:
    return AwsS3Client(Mock(get_bucket_lifecycle_configuration=Mock(side_effect=get_bucket_lifecycle)))


def test_get_bucket_lifecycle_single_rule() -> None:
    lifecycle = bucket_lifecycle(current_version_expiry="unset", previous_version_deletion="unset")
    assert lifecycle == s3_client_lifecycle().get_bucket_lifecycle("single-rule")


def test_get_bucket_lifecycle_multiple_rules() -> None:
    lifecycle = bucket_lifecycle(current_version_expiry=5, previous_version_deletion=10)
    assert lifecycle == s3_client_lifecycle().get_bucket_lifecycle("multiple-rules")


def test_get_bucket_lifecycle_disabled() -> None:
    lifecycle = bucket_lifecycle(current_version_expiry="unset", previous_version_deletion="unset")
    assert lifecycle == s3_client_lifecycle().get_bucket_lifecycle("disabled")


def test_get_bucket_lifecycle_no_expiry() -> None:
    lifecycle = bucket_lifecycle(current_version_expiry="unset", previous_version_deletion="unset")
    assert lifecycle == s3_client_lifecycle().get_bucket_lifecycle("no-expiry")


def test_get_bucket_lifecycle_not_set(caplog: Any) -> None:
    lifecycle = bucket_lifecycle(current_version_expiry="unset", previous_version_deletion="unset")
    with caplog.at_level(logging.WARNING):
        assert lifecycle == s3_client_lifecycle().get_bucket_lifecycle("no-lifecycle")
        assert "NoSuchLifecycleConfiguration" in caplog.text


def get_bucket_mfa(**kwargs: Dict[str, Any]) -> Any:
    buck = str(kwargs["Bucket"])
    if buck == "access-denied":
        raise client_error("GetBucketVersioning", "AccessDenied", "Access Denied")

    versioning_mapping: Dict[str, Any] = {
        "mfa-delete-enabled": responses.GET_BUCKET_VERSIONING_MFA_DELETE_ENABLED,
        "mfa-delete-disabled": responses.GET_BUCKET_VERSIONING_MFA_DELETE_DISABLED,
        "mfa-delete-unset": responses.GET_BUCKET_VERSIONING_MFA_DELETE_UNSET,
    }
    return versioning_mapping[buck]


def s3_client_mfa() -> AwsS3Client:
    return AwsS3Client(Mock(get_bucket_versioning=Mock(side_effect=get_bucket_mfa)))


def test_get_bucket_mfa_delete_enabled() -> None:
    mfa_delete = bucket_mfa_delete(enabled=True)
    assert mfa_delete == s3_client_mfa().get_bucket_mfa_delete("mfa-delete-enabled")


def test_get_bucket_mfa_delete_disabled() -> None:
    mfa_delete = bucket_mfa_delete(enabled=False)
    assert mfa_delete == s3_client_mfa().get_bucket_mfa_delete("mfa-delete-disabled")


def test_get_bucket_mfa_delete_unset() -> None:
    mfa_delete = bucket_mfa_delete(enabled=False)
    assert mfa_delete == s3_client_mfa().get_bucket_mfa_delete("mfa-delete-unset")


def test_get_bucket_mfa_delete_failure(caplog: Any) -> None:
    mfa_delete = bucket_mfa_delete(enabled=False)
    with caplog.at_level(logging.WARNING):
        assert mfa_delete == s3_client_mfa().get_bucket_mfa_delete("access-denied")
    assert "AccessDenied" in caplog.text


def s3_client_pab(public_access_block_response: Dict[str, Any]) -> AwsS3Client:
    return AwsS3Client(
        Mock(
            get_public_access_block=Mock(
                side_effect=lambda **kwargs: public_access_block_response
                if kwargs.get("Bucket") == "bucket"
                else _raise(client_error("GetPublicAccessBlock", "AccessDenied", "Access Denied")),
            )
        )
    )


def test_get_bucket_public_access_block() -> None:
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
        assert scenario["state"] == s3_client_pab(scenario["response"]).get_bucket_public_access_block("bucket")


def test_get_bucket_public_access_block_failure(caplog: Any) -> None:
    not_blocked = bucket_public_access_block(enabled=False)
    with caplog.at_level(logging.WARNING):
        assert not_blocked == s3_client_pab({}).get_bucket_public_access_block("denied")
        assert "AccessDenied" in caplog.text


def get_bucket_secure_transport(**kwargs: Dict[str, Any]) -> Any:
    buck = str(kwargs["Bucket"])
    if buck == "denied":
        raise client_error("GetBucketPolicy", "AccessDenied", "Access Denied")

    policy_mapping: Dict[str, Any] = {
        "bucket": responses.GET_BUCKET_POLICY,
        "secure-bucket": responses.GET_BUCKET_POLICY_SECURE_TRANSPORT,
    }
    return policy_mapping[buck]


def s3_client_secure_transport() -> AwsS3Client:
    return AwsS3Client(Mock(get_bucket_policy=Mock(side_effect=get_bucket_secure_transport)))


def test_get_bucket_secure_transport_disabled() -> None:
    secure_transport = bucket_secure_transport(enabled=False)
    assert secure_transport == s3_client_secure_transport().get_bucket_secure_transport("bucket")


def test_get_bucket_secure_transport_enabled() -> None:
    secure_transport = bucket_secure_transport(enabled=True)
    assert secure_transport == s3_client_secure_transport().get_bucket_secure_transport("secure-bucket")


def test_get_bucket_secure_transport_failure(caplog: Any) -> None:
    secure_transport = bucket_secure_transport(enabled=False)
    with caplog.at_level(logging.WARNING):
        assert secure_transport == s3_client_secure_transport().get_bucket_secure_transport("denied")
        assert "AccessDenied" in caplog.text


def get_bucket_versioning(**kwargs: Dict[str, Any]) -> Any:
    buck = str(kwargs["Bucket"])
    if buck == "access-denied":
        raise client_error("GetBucketVersioning", "AccessDenied", "Access Denied")

    versioning_mapping: Dict[str, Any] = {
        "versioning-enabled": responses.GET_BUCKET_VERSIONING_ENABLED,
        "versioning-suspended": responses.GET_BUCKET_VERSIONING_SUSPENDED,
        "versioning-unset": responses.GET_BUCKET_VERSIONING_UNSET,
    }
    return versioning_mapping[buck]


def s3_client_versioning() -> AwsS3Client:
    return AwsS3Client(Mock(get_bucket_versioning=Mock(side_effect=get_bucket_versioning)))


def test_get_bucket_versioning_enabled() -> None:
    versioning = bucket_versioning(enabled=True)
    assert versioning == s3_client_versioning().get_bucket_versioning("versioning-enabled")


def test_get_bucket_versioning_suspended() -> None:
    versioning = bucket_versioning(enabled=False)
    assert versioning == s3_client_versioning().get_bucket_versioning("versioning-suspended")


def test_get_bucket_versioning_unset() -> None:
    versioning = bucket_versioning(enabled=False)
    assert versioning == s3_client_versioning().get_bucket_versioning("versioning-unset")


def test_get_bucket_versioning_failure(caplog: Any) -> None:
    versioning = bucket_versioning(enabled=False)
    with caplog.at_level(logging.WARNING):
        assert versioning == s3_client_versioning().get_bucket_versioning("access-denied")
        assert "AccessDenied" in caplog.text


def put_object(**kwargs: Dict[str, Any]) -> Any:
    buck = str(kwargs["Bucket"])
    key = str(kwargs["Key"])
    body = str(kwargs["Body"])
    return (
        responses.PUT_OBJECT
        if buck == "buck" and key == "obj" and body == "bla"
        else _raise(client_error("PutObject", "AccessDenied", "Access Denied"))
    )


def s3_client_put_object() -> AwsS3Client:
    return AwsS3Client(Mock(put_object=Mock(side_effect=put_object)))


def test_put_object_success() -> None:
    assert "some id" == s3_client_put_object().put_object(bucket="buck", object_name="obj", object_content="bla")


def test_put_object_failure(caplog: Any) -> None:
    with caplog.at_level(logging.WARNING):
        s3_client_put_object().put_object(bucket="denied", object_name="obj", object_content="bla")
        assert "AccessDenied" in caplog.text


def test_get_bucket_policy() -> None:
    expected_policy = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:getObject", "Resource": "*"}]}
    s3_client = AwsS3Client(
        Mock(
            get_bucket_policy=Mock(
                side_effect=lambda **kwargs: responses.GET_BUCKET_POLICY if kwargs["Bucket"] == "some-bucket" else None
            )
        )
    )
    actual_policy = s3_client.get_bucket_policy("some-bucket")
    assert actual_policy == expected_policy


def test_get_bucket_policy_bucket_does_not_exist(caplog: Any) -> None:
    s3_client = AwsS3Client(
        Mock(get_bucket_policy=Mock(side_effect=client_error("GetBucketPolicy", "NoSuchBucket", "no")))
    )
    with caplog.at_level(logging.WARNING):
        assert s3_client.get_bucket_policy("boom") is None
        assert "NoSuchBucket" in caplog.text
        assert "boom" in caplog.text


def test_get_object() -> None:
    s3_client = AwsS3Client(
        Mock(
            get_object=Mock(
                side_effect=lambda **kwargs: responses.GET_OBJECT
                if kwargs["Bucket"] == "buck" and kwargs["Key"] == "fruit"
                else None
            )
        )
    )
    actual_object = s3_client.get_object("buck", "fruit")
    assert actual_object == "banana"
