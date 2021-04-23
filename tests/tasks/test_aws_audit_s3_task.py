from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from src.tasks.aws_audit_s3_task import AwsAuditS3Task

from tests.test_types_generator import account, bucket, bucket_encryption, bucket_logging, bucket_secure_transport


class TestAwsAuditS3Task(AwsScannerTestCase):
    def test_run_task(self) -> None:
        bucket_1, bucket_2, bucket_3 = "bucket-1", "bucket-2", "another_bucket"
        buckets = [bucket(bucket_1), bucket(bucket_2), bucket(bucket_3)]
        encryption_mapping = {
            bucket_1: bucket_encryption(enabled=True, type="cmk"),
            bucket_2: bucket_encryption(enabled=False),
            bucket_3: bucket_encryption(enabled=True, type="aws"),
        }
        logging_mapping = {
            bucket_1: bucket_logging(enabled=False),
            bucket_2: bucket_logging(enabled=False),
            bucket_3: bucket_logging(enabled=True),
        }
        secure_transport_mapping = {
            bucket_1: bucket_secure_transport(enabled=True),
            bucket_2: bucket_secure_transport(enabled=True),
            bucket_3: bucket_secure_transport(enabled=False),
        }

        s3_client = Mock(
            list_buckets=Mock(return_value=buckets),
            get_bucket_encryption=Mock(side_effect=lambda b: encryption_mapping[b]),
            get_bucket_logging=Mock(side_effect=lambda b: logging_mapping[b]),
            get_bucket_secure_transport=Mock(side_effect=lambda b: secure_transport_mapping[b]),
        )

        task_report = AwsAuditS3Task(account())._run_task(s3_client)
        self.assertEqual(
            {
                "buckets": [
                    bucket(
                        bucket_1,
                        bucket_encryption(enabled=True, type="cmk"),
                        bucket_logging(enabled=False),
                        bucket_secure_transport(enabled=True),
                    ),
                    bucket(
                        bucket_2,
                        bucket_encryption(enabled=False),
                        bucket_logging(enabled=False),
                        bucket_secure_transport(enabled=True),
                    ),
                    bucket(
                        bucket_3,
                        bucket_encryption(enabled=True, type="aws"),
                        bucket_logging(enabled=True),
                        bucket_secure_transport(enabled=False),
                    ),
                ]
            },
            task_report,
        )
