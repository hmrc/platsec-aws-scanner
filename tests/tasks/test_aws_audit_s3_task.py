from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from src.tasks.aws_audit_s3_task import AwsAuditS3Task

from tests.test_types_generator import (
    account,
    bucket,
    bucket_content_deny,
    bucket_data_tagging,
    bucket_encryption,
    bucket_lifecycle,
    bucket_logging,
    bucket_mfa_delete,
    bucket_public_access_block,
    bucket_secure_transport,
    bucket_versioning,
)


class TestAwsAuditS3Task(AwsScannerTestCase):
    def test_run_task(self) -> None:
        bucket_1, bucket_2, bucket_3 = "bucket-1", "bucket-2", "another_bucket"
        buckets = [bucket(bucket_1), bucket(bucket_2), bucket(bucket_3)]
        content_deny_mapping = {
            bucket_1: bucket_content_deny(enabled=False),
            bucket_2: bucket_content_deny(enabled=True),
            bucket_3: bucket_content_deny(enabled=True),
        }
        data_tagging = {
            bucket_1: bucket_data_tagging(expiry="6-months", sensitivity="low"),
            bucket_2: bucket_data_tagging(expiry="1-month", sensitivity="high"),
            bucket_3: bucket_data_tagging(expiry="1-week", sensitivity="high"),
        }
        encryption_mapping = {
            bucket_1: bucket_encryption(enabled=True, type="cmk"),
            bucket_2: bucket_encryption(enabled=False),
            bucket_3: bucket_encryption(enabled=True, type="aws"),
        }
        lifecycle_mapping = {
            bucket_1: bucket_lifecycle(current_version_expiry=7, previous_version_deletion=14),
            bucket_2: bucket_lifecycle(current_version_expiry=31, previous_version_deletion="unset"),
            bucket_3: bucket_lifecycle(current_version_expiry="unset", previous_version_deletion=366),
        }
        logging_mapping = {
            bucket_1: bucket_logging(enabled=False),
            bucket_2: bucket_logging(enabled=False),
            bucket_3: bucket_logging(enabled=True),
        }
        mfa_delete_mapping = {
            bucket_1: bucket_mfa_delete(enabled=True),
            bucket_2: bucket_mfa_delete(enabled=False),
            bucket_3: bucket_mfa_delete(enabled=True),
        }
        public_access_block_mapping = {
            bucket_1: bucket_public_access_block(enabled=False),
            bucket_2: bucket_public_access_block(enabled=True),
            bucket_3: bucket_public_access_block(enabled=True),
        }
        secure_transport_mapping = {
            bucket_1: bucket_secure_transport(enabled=True),
            bucket_2: bucket_secure_transport(enabled=True),
            bucket_3: bucket_secure_transport(enabled=False),
        }
        versioning_mapping = {
            bucket_1: bucket_versioning(enabled=True),
            bucket_2: bucket_versioning(enabled=True),
            bucket_3: bucket_versioning(enabled=False),
        }

        s3_client = Mock(
            list_buckets=Mock(return_value=buckets),
            get_bucket_content_deny=Mock(side_effect=lambda b: content_deny_mapping[b]),
            get_bucket_data_tagging=Mock(side_effect=lambda b: data_tagging[b]),
            get_bucket_encryption=Mock(side_effect=lambda b: encryption_mapping[b]),
            get_bucket_lifecycle=Mock(side_effect=lambda b: lifecycle_mapping[b]),
            get_bucket_logging=Mock(side_effect=lambda b: logging_mapping[b]),
            get_bucket_mfa_delete=Mock(side_effect=lambda b: mfa_delete_mapping[b]),
            get_bucket_public_access_block=Mock(side_effect=lambda b: public_access_block_mapping[b]),
            get_bucket_secure_transport=Mock(side_effect=lambda b: secure_transport_mapping[b]),
            get_bucket_versioning=Mock(side_effect=lambda b: versioning_mapping[b]),
        )

        task_report = AwsAuditS3Task(account())._run_task(s3_client)
        self.assertEqual(
            {
                "buckets": [
                    bucket(
                        name=bucket_1,
                        content_deny=bucket_content_deny(enabled=False),
                        data_tagging=bucket_data_tagging(expiry="6-months", sensitivity="low"),
                        encryption=bucket_encryption(enabled=True, type="cmk"),
                        lifecycle=bucket_lifecycle(current_version_expiry=7, previous_version_deletion=14),
                        logging=bucket_logging(enabled=False),
                        mfa_delete=bucket_mfa_delete(enabled=True),
                        public_access_block=bucket_public_access_block(enabled=False),
                        secure_transport=bucket_secure_transport(enabled=True),
                        versioning=bucket_versioning(enabled=True),
                    ),
                    bucket(
                        name=bucket_2,
                        content_deny=bucket_content_deny(enabled=True),
                        data_tagging=bucket_data_tagging(expiry="1-month", sensitivity="high"),
                        encryption=bucket_encryption(enabled=False),
                        lifecycle=bucket_lifecycle(current_version_expiry=31, previous_version_deletion="unset"),
                        logging=bucket_logging(enabled=False),
                        mfa_delete=bucket_mfa_delete(enabled=False),
                        public_access_block=bucket_public_access_block(enabled=True),
                        secure_transport=bucket_secure_transport(enabled=True),
                        versioning=bucket_versioning(enabled=True),
                    ),
                    bucket(
                        name=bucket_3,
                        content_deny=bucket_content_deny(enabled=True),
                        data_tagging=bucket_data_tagging(expiry="1-week", sensitivity="high"),
                        encryption=bucket_encryption(enabled=True, type="aws"),
                        lifecycle=bucket_lifecycle(current_version_expiry="unset", previous_version_deletion=366),
                        logging=bucket_logging(enabled=True),
                        mfa_delete=bucket_mfa_delete(enabled=True),
                        public_access_block=bucket_public_access_block(enabled=True),
                        secure_transport=bucket_secure_transport(enabled=False),
                        versioning=bucket_versioning(enabled=False),
                    ),
                ]
            },
            task_report,
        )
