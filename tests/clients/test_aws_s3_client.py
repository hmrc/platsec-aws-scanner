from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from src.clients.aws_s3_client import AwsS3Client

from tests.clients import test_aws_s3_client_responses as responses


def s3_client() -> AwsS3Client:
    return AwsS3Client(mock_s3_boto_client())


def mock_s3_boto_client() -> Mock:
    return Mock(list_buckets=Mock(return_value=responses.LIST_BUCKETS))


class TestAwsS3Client(AwsScannerTestCase):
    def test_list_buckets(self) -> None:
        self.assertEqual(responses.EXPECTED_LIST_BUCKETS, s3_client().list_buckets())
