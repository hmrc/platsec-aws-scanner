from unittest import TestCase
from unittest.mock import Mock, call, patch

from typing import Any, Dict, Type

from src.data.aws_scanner_exceptions import CloudtrailException
from src.clients.aws_cloudtrail_client import AwsCloudtrailClient
from tests.clients.test_aws_cloudtrail_responses import (
    LIST_TRAILS_RESPONSE_ONE,
    LIST_TRAILS_RESPONSE_TWO,
    LIST_TRAILS_RESPONSE_WITH_TOKEN,
)
from src.aws_scanner_config import AwsScannerConfig as Config
from tests.test_types_generator import account, partition


class TestListTrails(TestCase):
    def test_trails_return_one(self) -> None:
        boto_cloudtrail = Mock(list_trails=Mock(return_value=LIST_TRAILS_RESPONSE_ONE))
        client = AwsCloudtrailClient(boto_cloudtrail)
        expected = {
            "Trails": [
                {
                    "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-1",
                    "Name": "test_trail_001",
                    "HomeRegion": "eu-west-2",
                }
            ]
        }
        got = client.get_trails()
        self.assertEqual(expected, got)

    def test_trails_return_two(self) -> None:
        boto_cloudtrail = Mock(list_trails=Mock(return_value=LIST_TRAILS_RESPONSE_TWO))
        client = AwsCloudtrailClient(boto_cloudtrail)
        expected = {
            "Trails": [
                {
                    "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-1",
                    "Name": "test_trail_001",
                    "HomeRegion": "eu-west-2",
                },
                {
                    "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-2",
                    "Name": "test_trail_002",
                    "HomeRegion": "eu-west-2",
                },
            ]
        }
        got = client.get_trails()
        self.assertEqual(expected, got)

    def test_trails_return_token(self) -> None:
        boto_cloudtrail = Mock(list_trails=Mock(return_value=LIST_TRAILS_RESPONSE_WITH_TOKEN))
        client = AwsCloudtrailClient(boto_cloudtrail)
        expected = {
            "Trails": [
                {
                    "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-1",
                    "Name": "test_trail_001",
                    "HomeRegion": "eu-west-2",
                },
                {
                    "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-2",
                    "Name": "test_trail_002",
                    "HomeRegion": "eu-west-2",
                },
            ],
            "NextToken": "xyxyxxyy",
        }
        got = client.get_trails()
        self.assertEqual(expected, got)
