from unittest import TestCase
from unittest.mock import Mock

from src.tasks.aws_audit_cloudtrail_task import AwsAuditCloudtrailTask

from tests.test_types_generator import account, cloudtrail_audit_task, Trail


class TestAwsAuditCloudtrailTask(TestCase):
    def test_run_task(self) -> None:
        trail_1, trail_2, trail_3 = "trail-1", "trail-2", "trail-this"
        trails = [Trail(trail_1), Trail(trail_2), Trail(trail_3)]

        logfile_encryption_mapping = {
            trail_1: logfile_encryption_at_rest(enabled=True, type="cmk"),
        }

        logfile_validation_mapping = {
            trail_1: logfile_encryption_at_rest(enabled=True, type="cmk"),
        }

        cloudtrail_audit_client = Mock(
            get_trails=Mock(return_value=trails),
            check_logfile_validation_enabled=Mock(return_value=True),
            check_logfile_encryption=Mock(return_value={}),
        )

        task_report = AwsAuditCloudtrailTask(account())._run_task(cloudtrail_audit_client)
        self.assertEqual(
            {
                "trails": [
                    Trail(
                        name="trail_1",
                        LogFileValidationEnabled=True,
                        KmsKeyId="arn:aws:kms:eu-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
                    ),
                ]
            },
            task_report,
        )
