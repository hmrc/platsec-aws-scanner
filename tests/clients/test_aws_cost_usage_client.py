from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from src.clients.aws_cost_usage_client import AwsCostUsageClient


class TestAwsCostUsageClient(AwsScannerTestCase):

    @staticmethod
    def cost_usage_client(self) -> AwsCostUsageClient:
        return AwsCostUsageClient(Mock())

    def test_get_aws_cost_usage(self) -> None:
        client = AwsCostUsageClient(Mock())

        self.assertEqual(client.get_aws_cost_usage("s3"), {})
