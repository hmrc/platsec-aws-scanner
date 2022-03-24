from unittest import TestCase
from unittest.mock import Mock

from src.clients.composite.aws_s3_kms_client import AwsS3KmsClient
from src.tasks.aws_audit_s3_task import AwsAuditS3Task

from tests.test_types_generator import (
    account,
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
    key,
)


class TestAwsAuditS3Task(TestCase):
    def test_run_task(self) -> None:
        bucket_1, bucket_2, bucket_3 = "bucket-1", "bucket-2", "another_bucket"
        buckets = [bucket(bucket_1), bucket(bucket_2), bucket(bucket_3)]
        key_1, key_2, key_3 = "key-1", "key-2", "key-3"

        acl_mapping = {
            bucket_1: bucket_acl(all_users_enabled=True, authenticated_users_enabled=False),
            bucket_2: bucket_acl(all_users_enabled=False, authenticated_users_enabled=True),
            bucket_3: bucket_acl(all_users_enabled=False, authenticated_users_enabled=False),
        }
        content_deny_mapping = {
            bucket_1: bucket_content_deny(enabled=False),
            bucket_2: bucket_content_deny(enabled=True),
            bucket_3: bucket_content_deny(enabled=True),
        }
        cors_mapping = {
            bucket_1: bucket_cors(enabled=True),
            bucket_2: bucket_cors(enabled=False),
            bucket_3: bucket_cors(enabled=False),
        }
        data_tagging = {
            bucket_1: bucket_data_tagging(expiry="6-months", sensitivity="low"),
            bucket_2: bucket_data_tagging(expiry="1-month", sensitivity="high"),
            bucket_3: bucket_data_tagging(expiry="1-week", sensitivity="high"),
        }
        encryption_mapping = {
            bucket_1: bucket_encryption(enabled=True, type="cmk", key_id="key-1"),
            bucket_2: bucket_encryption(enabled=False),
            bucket_3: bucket_encryption(enabled=True, type="aws", key_id="key-3"),
        }
        kms_key_mapping = {
            key_1: key(id="key-1", rotation_enabled=True),
            key_2: None,
            key_3: key(id="key-3", rotation_enabled=False),
        }
        lifecycle_mapping = {
            bucket_1: bucket_lifecycle(current_version_expiry=7, previous_version_deletion=14, compliant=True),
            bucket_2: bucket_lifecycle(current_version_expiry=31, previous_version_deletion="unset", compliant=False),
            bucket_3: bucket_lifecycle(current_version_expiry="unset", previous_version_deletion=366, compliant=False),
        }
        logging_mapping = {
            bucket_1: bucket_logging(enabled=False, compliant=False),
            bucket_2: bucket_logging(enabled=False, compliant=False),
            bucket_3: bucket_logging(enabled=True, compliant=True),
        }
        mfa_delete_mapping = {
            bucket_1: bucket_mfa_delete(enabled=True, compliant=True),
            bucket_2: bucket_mfa_delete(enabled=False, compliant=True),  # We don't check for mfa-delete so default true
            bucket_3: bucket_mfa_delete(enabled=True, compliant=True),
        }
        public_access_block_mapping = {
            bucket_1: bucket_public_access_block(enabled=False, compliant=False),
            bucket_2: bucket_public_access_block(enabled=True, compliant=True),
            bucket_3: bucket_public_access_block(enabled=True, compliant=True),
        }
        secure_transport_mapping = {
            bucket_1: bucket_secure_transport(enabled=True, compliant=True),
            bucket_2: bucket_secure_transport(enabled=True, compliant=True),
            bucket_3: bucket_secure_transport(enabled=False, compliant=False),
        }
        versioning_mapping = {
            bucket_1: bucket_versioning(enabled=True, compliant=True),
            bucket_2: bucket_versioning(enabled=True, compliant=True),
            bucket_3: bucket_versioning(enabled=False, compliant=False),
        }

        s3_client = Mock(
            list_buckets=Mock(return_value=buckets),
            get_bucket_acl=Mock(side_effect=lambda b: acl_mapping[b]),
            get_bucket_content_deny=Mock(side_effect=lambda b: content_deny_mapping[b]),
            get_bucket_cors=Mock(side_effect=lambda b: cors_mapping[b]),
            get_bucket_data_tagging=Mock(side_effect=lambda b: data_tagging[b]),
            get_bucket_encryption=Mock(side_effect=lambda b: encryption_mapping[b]),
            get_bucket_lifecycle=Mock(side_effect=lambda b: lifecycle_mapping[b]),
            get_bucket_logging=Mock(side_effect=lambda b: logging_mapping[b]),
            get_bucket_mfa_delete=Mock(side_effect=lambda b: mfa_delete_mapping[b]),
            get_bucket_public_access_block=Mock(side_effect=lambda b: public_access_block_mapping[b]),
            get_bucket_secure_transport=Mock(side_effect=lambda b: secure_transport_mapping[b]),
            get_bucket_versioning=Mock(side_effect=lambda b: versioning_mapping[b]),
        )
        kms_client = Mock(find_key=Mock(side_effect=lambda b: kms_key_mapping[b]))
        s3_kms_client = AwsS3KmsClient(s3=s3_client, kms=kms_client)

        task_report = AwsAuditS3Task(account())._run_task(s3_kms_client)
        self.maxDiff = None

        assert task_report["buckets"][0] == bucket(
            name=bucket_1,
            acl=bucket_acl(all_users_enabled=True, authenticated_users_enabled=False, compliant=False),
            content_deny=bucket_content_deny(enabled=False, compliant=False),
            cors=bucket_cors(enabled=True, compliant=False),
            data_tagging=bucket_data_tagging(expiry="6-months", sensitivity="low", compliant=True),
            encryption=bucket_encryption(enabled=True, type="cmk", key_id="key-1", compliant=True),
            kms_key=key(id="key-1", rotation_enabled=True, compliant=True),
            lifecycle=bucket_lifecycle(current_version_expiry=7, previous_version_deletion=14, compliant=True),
            logging=bucket_logging(enabled=False, compliant=False),
            mfa_delete=bucket_mfa_delete(enabled=True, compliant=True),
            public_access_block=bucket_public_access_block(enabled=False, compliant=False),
            secure_transport=bucket_secure_transport(enabled=True, compliant=True),
            versioning=bucket_versioning(enabled=True, compliant=True),
        )

        assert task_report["buckets"][1] == bucket(
            name=bucket_2,
            acl=bucket_acl(all_users_enabled=False, authenticated_users_enabled=True, compliant=False),
            content_deny=bucket_content_deny(enabled=True, compliant=True),
            cors=bucket_cors(enabled=False, compliant=True),
            data_tagging=bucket_data_tagging(expiry="1-month", sensitivity="high", compliant=True),
            encryption=bucket_encryption(enabled=False, compliant=False),
            kms_key=None,
            lifecycle=bucket_lifecycle(current_version_expiry=31, previous_version_deletion="unset", compliant=False),
            logging=bucket_logging(enabled=False, compliant=False),
            mfa_delete=bucket_mfa_delete(enabled=False, compliant=True),
            public_access_block=bucket_public_access_block(enabled=True, compliant=True),
            secure_transport=bucket_secure_transport(enabled=True, compliant=True),
            versioning=bucket_versioning(enabled=True, compliant=True),
        )

        assert task_report["buckets"][2] == bucket(
            name=bucket_3,
            acl=bucket_acl(all_users_enabled=False, authenticated_users_enabled=False, compliant=True),
            content_deny=bucket_content_deny(enabled=True, compliant=True),
            cors=bucket_cors(enabled=False, compliant=True),
            data_tagging=bucket_data_tagging(expiry="1-week", sensitivity="high", compliant=True),
            encryption=bucket_encryption(enabled=True, type="aws", key_id="key-3", compliant=True),
            kms_key=key(id="key-3", rotation_enabled=False, compliant=False),
            lifecycle=bucket_lifecycle(current_version_expiry="unset", previous_version_deletion=366, compliant=False),
            logging=bucket_logging(enabled=True, compliant=True),
            mfa_delete=bucket_mfa_delete(enabled=True, compliant=True),
            public_access_block=bucket_public_access_block(enabled=True, compliant=True),
            secure_transport=bucket_secure_transport(enabled=False, compliant=False),
            versioning=bucket_versioning(enabled=False, compliant=False),
        )
