from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from src.tasks.aws_audit_s3_task import AwsAuditS3Task

from tests.test_types_generator import account, bucket


class TestAwsAuditS3Task(AwsScannerTestCase):
    def test_run_task(self) -> None:
        buckets = [bucket("bucket-1"), bucket("bucket-2"), bucket("another-bucket")]
        s3_client = Mock(list_buckets=Mock(return_value=buckets))
        task_report = AwsAuditS3Task(account())._run_task(s3_client)
        self.assertEqual({"buckets": buckets}, task_report)
