from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from src.tasks.aws_audit_s3_task import AwsAuditS3Task

from tests.test_types_generator import account, bucket, bucket_encryption


class TestAwsAuditS3Task(AwsScannerTestCase):
    def test_run_task(self) -> None:
        buckets = [bucket("bucket-1"), bucket("bucket-2"), bucket("another-bucket")]
        encryption_mapping = {
            "bucket-1": bucket_encryption(enabled=True, type="cmk"),
            "bucket-2": bucket_encryption(enabled=False),
            "another-bucket": bucket_encryption(enabled=True, type="aws"),
        }

        s3_client = Mock(
            list_buckets=Mock(return_value=buckets),
            get_bucket_encryption=Mock(side_effect=lambda b: encryption_mapping[b]),
        )

        task_report = AwsAuditS3Task(account())._run_task(s3_client)
        self.assertEqual(
            {
                "buckets": [
                    bucket("bucket-1", bucket_encryption(enabled=True, type="cmk")),
                    bucket("bucket-2", bucket_encryption(enabled=False)),
                    bucket("another-bucket", bucket_encryption(enabled=True, type="aws")),
                ]
            },
            task_report,
        )
