from unittest import TestCase
from unittest.mock import Mock

from typing import Any, Dict, Type

from src.data.aws_scanner_exceptions import CloudtrailException
from botocore.exceptions import BotoCoreError
from src.clients.aws_cloudtrail_audit_client import AwsCloudtrailAuditClient
from tests.clients.test_aws_cloudtrail_responses import (
    DESCRIBE_TRAILS_RESPONSE_TWO,
    DESCRIBE_TRAILS_RESPONSE_ONE,
)
from src.aws_scanner_config import AwsScannerConfig as Config


class TestCheckLogFileEncryptionIsEnabled(TestCase):
    def test_check_logfile_encryption_enabled_success(self) -> None:
        boto_cloudtrail = Mock(describe_trails=Mock())
        client = AwsCloudtrailAuditClient(boto_cloudtrail)
        trail = {
            "Name": "dummy-trail-1",
            "HomeRegion": "eu-west-2",
            "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-1",
            "LogFileValidationEnabled": True,
            "KmsKeyId": "arn:aws:kms:eu-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
        }
        self.assertEqual(True, client.check_logfile_encryption(trail))

    def test_check_logfile_encryption_not_enabled_success(self) -> None:
        boto_cloudtrail = Mock(describe_trails=Mock())
        client = AwsCloudtrailAuditClient(boto_cloudtrail)
        trail = {
            "Name": "dummy-trail-1",
            "HomeRegion": "eu-west-2",
            "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-1",
            "LogFileValidationEnabled": False,
        }
        self.assertEqual(False, client.check_logfile_encryption(trail))

    def test_check_logfile_encryption_regex_fail(self) -> None:
        boto_cloudtrail = Mock(describe_trails=Mock())
        client = AwsCloudtrailAuditClient(boto_cloudtrail)
        trail = {
            "Name": "dummy-trail-1",
            "HomeRegion": "eu-west-2",
            "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-1",
            "LogFileValidationEnabled": False,
            "KmsKeyId": "not_a_real_arn",
        }
        self.assertEqual(False, client.check_logfile_encryption(trail))


class TestCheckLogFileValidationIsEnabled(TestCase):
    def test_check_logfile_validation_enabled_success(self) -> None:
        boto_cloudtrail = Mock(describe_trails=Mock())
        client = AwsCloudtrailAuditClient(boto_cloudtrail)
        trail = {
            "Name": "dummy-trail-1",
            "HomeRegion": "eu-west-2",
            "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-1",
            "LogFileValidationEnabled": True,
            "KmsKeyId": "arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012",
        }
        self.assertEqual(True, client.check_logfile_validation_enabled(trail))

    def test_check_logfile_validation_not_enabled_success(self) -> None:
        boto_cloudtrail = Mock(describe_trails=Mock())
        client = AwsCloudtrailAuditClient(boto_cloudtrail)
        trail = {
            "Name": "dummy-trail-1",
            "HomeRegion": "eu-west-2",
            "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-1",
            "LogFileValidationEnabled": False,
            "KmsKeyId": "arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012",
        }
        self.assertEqual(False, client.check_logfile_validation_enabled(trail))

    def test_check_logfile_validation_enabled_no_trail(self) -> None:
        boto_cloudtrail = Mock(describe_trails=Mock())
        client = AwsCloudtrailAuditClient(boto_cloudtrail)
        with self.assertRaises(CloudtrailException):
            client.check_logfile_validation_enabled({})

    def test_check_logfile_validation_enabled_no_logfilevalidation(self) -> None:
        boto_cloudtrail = Mock(describe_trails=Mock())
        client = AwsCloudtrailAuditClient(boto_cloudtrail)
        trail = {
            "Name": "dummy-trail-1",
            "HomeRegion": "eu-west-2",
            "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-1",
            "KmsKeyId": "arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012",
        }
        with self.assertRaises(CloudtrailException):
            client.check_logfile_validation_enabled(trail)

    def test_check_logfile_validation_enabled_no_bool(self) -> None:
        boto_cloudtrail = Mock(describe_trails=Mock())
        client = AwsCloudtrailAuditClient(boto_cloudtrail)
        trail = {
            "Name": "dummy-trail-1",
            "HomeRegion": "eu-west-2",
            "LogFileValidationEnabled": "yes",
            "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-1",
            "KmsKeyId": "arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012",
        }
        with self.assertRaisesRegex(CloudtrailException, "unable to determine logfile validation status"):
            client.check_logfile_validation_enabled(trail)


class TestDescribeTrails(TestCase):
    def test_describe_trails_return_empty(self) -> None:
        boto_cloudtrail = Mock(describe_trails=Mock(return_value={"trailList": []}))
        client = AwsCloudtrailAuditClient(boto_cloudtrail)
        expected = {"trailList": []}

        self.assertEqual(expected, client.get_trails())

    def test_describe_trails_return_one(self) -> None:
        boto_cloudtrail = Mock(describe_trails=Mock(return_value=DESCRIBE_TRAILS_RESPONSE_ONE))
        client = AwsCloudtrailAuditClient(boto_cloudtrail)
        expected = {
            "trailList": [
                {
                    "Name": "dummy-trail-1",
                    "HomeRegion": "eu-west-2",
                    "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-1",
                    "LogFileValidationEnabled": True,
                    "KmsKeyId": "arn:aws:kms:eu-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
                },
            ]
        }

        self.assertEqual(expected, client.get_trails())

    def test_describe_trails_return_two(self) -> None:
        boto_cloudtrail = Mock(describe_trails=Mock(return_value=DESCRIBE_TRAILS_RESPONSE_TWO))
        client = AwsCloudtrailAuditClient(boto_cloudtrail)
        expected = {
            "trailList": [
                {
                    "Name": "dummy-trail-1",
                    "HomeRegion": "eu-west-2",
                    "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-1",
                    "LogFileValidationEnabled": True,
                    "KmsKeyId": "arn:aws:kms:eu-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
                },
                {
                    "Name": "dummy-trail-2",
                    "HomeRegion": "eu-west-2",
                    "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-2",
                    "LogFileValidationEnabled": True,
                    "KmsKeyId": "arn:aws:kms:eu-west-2:123456789012:key/12345678-1234-1234-1234-123456789013",
                },
            ]
        }

        self.assertEqual(expected, client.get_trails())

    def test_describe_trails_raises(self) -> None:
        boto_cloudtrail = Mock(describe_trails=Mock(side_effect=BotoCoreError))
        client = AwsCloudtrailAuditClient(boto_cloudtrail)

        with self.assertRaisesRegex(CloudtrailException, f"unable to get trails"):
            client.get_trails()
