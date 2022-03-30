from unittest import TestCase
from unittest.mock import Mock

from src.clients.composite.aws_s3_kms_client import AwsS3KmsClient
from src.tasks.aws_audit_s3_task import AwsAuditS3Task

from tests.test_types_generator import (
    account,
    bucket,
    bucket_acl,
    bucket_compliancy,
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
        bucket_1, bucket_2, bucket_3, bucket_4 = "bucket-1", "bucket-2", "another_bucket", "forever-config-bucket"
        buckets = [bucket(bucket_1), bucket(bucket_2), bucket(bucket_3), bucket(bucket_4)]
        key_1, key_2, key_3, key_4 = "key-1", "key-2", "key-3", "key-4"

        acl_mapping = {
            bucket_1: bucket_acl(all_users_enabled=True, authenticated_users_enabled=False),
            bucket_2: bucket_acl(all_users_enabled=False, authenticated_users_enabled=True),
            bucket_3: bucket_acl(all_users_enabled=False, authenticated_users_enabled=False),
            bucket_4: bucket_acl(all_users_enabled=False, authenticated_users_enabled=False),
        }
        content_deny_mapping = {
            bucket_1: bucket_content_deny(enabled=False),
            bucket_2: bucket_content_deny(enabled=True),
            bucket_3: bucket_content_deny(enabled=True),
            bucket_4: bucket_content_deny(enabled=True),
        }
        cors_mapping = {
            bucket_1: bucket_cors(enabled=True),
            bucket_2: bucket_cors(enabled=False),
            bucket_3: bucket_cors(enabled=False),
            bucket_4: bucket_cors(enabled=False),
        }
        data_tagging = {
            bucket_1: bucket_data_tagging(expiry="6-months", sensitivity="low"),
            bucket_2: bucket_data_tagging(expiry="1-month", sensitivity="high"),
            bucket_3: bucket_data_tagging(expiry="1-week", sensitivity="high"),
            bucket_4: bucket_data_tagging(expiry="forever-config-only", sensitivity="low"),
        }
        encryption_mapping = {
            bucket_1: bucket_encryption(enabled=True, type="cmk", key_id="key-1"),
            bucket_2: bucket_encryption(enabled=False),
            bucket_3: bucket_encryption(enabled=True, type="aes", key_id=None),
            bucket_4: bucket_encryption(enabled=True, type="cmk", key_id="key-4"),
        }
        kms_key_mapping = {
            key_1: key(id="key-1", rotation_enabled=True),
            key_2: None,
            key_3: None,
            key_4: key(id="key-4", rotation_enabled=True),
        }
        lifecycle_mapping = {
            bucket_1: bucket_lifecycle(current_version_expiry=7, previous_version_deletion=14),
            bucket_2: bucket_lifecycle(current_version_expiry=31, previous_version_deletion="unset"),
            bucket_3: bucket_lifecycle(current_version_expiry="unset", previous_version_deletion=366),
            bucket_4: bucket_lifecycle(current_version_expiry="unset", previous_version_deletion="unset"),
        }
        logging_mapping = {
            bucket_1: bucket_logging(enabled=False),
            bucket_2: bucket_logging(enabled=False),
            bucket_3: bucket_logging(enabled=True),
            bucket_4: bucket_logging(enabled=True),
        }
        mfa_delete_mapping = {
            bucket_1: bucket_mfa_delete(enabled=True),
            bucket_2: bucket_mfa_delete(enabled=False),  # We don't check for mfa-delete so default true
            bucket_3: bucket_mfa_delete(enabled=True),
            bucket_4: bucket_mfa_delete(enabled=False),
        }
        public_access_block_mapping = {
            bucket_1: bucket_public_access_block(enabled=False),
            bucket_2: bucket_public_access_block(enabled=True),
            bucket_3: bucket_public_access_block(enabled=True),
            bucket_4: bucket_public_access_block(enabled=True),
        }
        secure_transport_mapping = {
            bucket_1: bucket_secure_transport(enabled=True),
            bucket_2: bucket_secure_transport(enabled=True),
            bucket_3: bucket_secure_transport(enabled=False),
            bucket_4: bucket_secure_transport(enabled=True),
        }
        versioning_mapping = {
            bucket_1: bucket_versioning(enabled=True),
            bucket_2: bucket_versioning(enabled=True),
            bucket_3: bucket_versioning(enabled=False),
            bucket_4: bucket_versioning(enabled=False),
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
            compliancy=bucket_compliancy(
                content_deny=False,
                acl=False,
                encryption=True,
                logging=False,
                public_access_block=False,
                secure_transport=True,
                versioning=True,
                mfa_delete=False,
                kms_key=True,
                tagging=True,
                lifecycle=True,
                cors=False,
            ),
            acl=bucket_acl(all_users_enabled=True, authenticated_users_enabled=False),
            content_deny=bucket_content_deny(enabled=False),
            cors=bucket_cors(enabled=True),
            data_tagging=bucket_data_tagging(expiry="6-months", sensitivity="low"),
            encryption=bucket_encryption(enabled=True, type="cmk", key_id="key-1"),
            kms_key=key(id="key-1", rotation_enabled=True),
            lifecycle=bucket_lifecycle(current_version_expiry=7, previous_version_deletion=14),
            logging=bucket_logging(enabled=False),
            mfa_delete=bucket_mfa_delete(enabled=True),
            public_access_block=bucket_public_access_block(enabled=False),
            secure_transport=bucket_secure_transport(enabled=True),
            versioning=bucket_versioning(enabled=True),
        )

        assert task_report["buckets"][1] == bucket(
            name=bucket_2,
            compliancy=bucket_compliancy(
                content_deny=True,
                acl=False,
                encryption=False,
                logging=False,
                public_access_block=True,
                secure_transport=True,
                versioning=True,
                mfa_delete=True,
                kms_key=False,
                tagging=True,
                lifecycle=False,
                cors=True,
            ),
            acl=bucket_acl(all_users_enabled=False, authenticated_users_enabled=True),
            content_deny=bucket_content_deny(enabled=True),
            cors=bucket_cors(enabled=False),
            data_tagging=bucket_data_tagging(expiry="1-month", sensitivity="high"),
            encryption=bucket_encryption(enabled=False),
            kms_key=None,
            lifecycle=bucket_lifecycle(current_version_expiry=31, previous_version_deletion="unset"),
            logging=bucket_logging(enabled=False),
            mfa_delete=bucket_mfa_delete(enabled=False),
            public_access_block=bucket_public_access_block(enabled=True),
            secure_transport=bucket_secure_transport(enabled=True),
            versioning=bucket_versioning(enabled=True),
        )

        assert task_report["buckets"][2] == bucket(
            name=bucket_3,
            compliancy=bucket_compliancy(
                content_deny=True,
                acl=True,
                encryption=True,
                logging=True,
                public_access_block=True,
                secure_transport=False,
                versioning=False,
                mfa_delete=False,
                kms_key=True,
                tagging=True,
                lifecycle=False,
                cors=True,
            ),
            acl=bucket_acl(all_users_enabled=False, authenticated_users_enabled=False),
            content_deny=bucket_content_deny(enabled=True),
            cors=bucket_cors(enabled=False),
            data_tagging=bucket_data_tagging(expiry="1-week", sensitivity="high"),
            encryption=bucket_encryption(enabled=True, type="aes", key_id=None),
            kms_key=None,
            lifecycle=bucket_lifecycle(current_version_expiry="unset", previous_version_deletion=366),
            logging=bucket_logging(enabled=True),
            mfa_delete=bucket_mfa_delete(enabled=True),
            public_access_block=bucket_public_access_block(enabled=True),
            secure_transport=bucket_secure_transport(enabled=False),
            versioning=bucket_versioning(enabled=False),
        )

        assert task_report["buckets"][3] == bucket(
            name=bucket_4,
            compliancy=bucket_compliancy(
                content_deny=True,
                acl=True,
                encryption=True,
                logging=True,
                public_access_block=True,
                secure_transport=True,
                versioning=False,
                mfa_delete=True,
                kms_key=True,
                tagging=True,
                lifecycle=True,
                cors=True,
            ),
            acl=bucket_acl(all_users_enabled=False, authenticated_users_enabled=False),
            content_deny=bucket_content_deny(enabled=True),
            cors=bucket_cors(enabled=False),
            data_tagging=bucket_data_tagging(expiry="forever-config-only", sensitivity="low"),
            encryption=bucket_encryption(enabled=True, type="cmk", key_id="key-4"),
            kms_key=key(id="key-4", rotation_enabled=True),
            lifecycle=bucket_lifecycle(current_version_expiry="unset", previous_version_deletion="unset"),
            logging=bucket_logging(enabled=True),
            mfa_delete=bucket_mfa_delete(enabled=False),
            public_access_block=bucket_public_access_block(enabled=True),
            secure_transport=bucket_secure_transport(enabled=True),
            versioning=bucket_versioning(enabled=False),
        )
