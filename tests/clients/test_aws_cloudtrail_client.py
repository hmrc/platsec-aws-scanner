from unittest import TestCase
from unittest.mock import Mock, call, patch

from typing import Any, Dict, Type

from src.data.aws_scanner_exceptions import CloudtrailException
from src.clients.aws_cloudtrail_client import AwsCloudtrailClient
from tests.clients.test_aws_cloudtrail_responses import LIST_TRAILS_RESPONSE_ONE
from tests.test_types_generator import account, partition


class TestList(TestCase):
    def test_trail_one(self) -> None:
        boto_cloudtrail = Mock(list_trails=Mock(return_value=LIST_TRAILS_RESPONSE_ONE))
        client = AwsCloudtrailClient(boto_cloudtrail)
        expected = {
            "Trails": [
                {
                    "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail",
                    "Name": "test_trail_001",
                    "HomeRegion": "eu-west-2",
                },
            ]
        }
        got = client.get_trails()
        self.assertEqual(expected, got)
