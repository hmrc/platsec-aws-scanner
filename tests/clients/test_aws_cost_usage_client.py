from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, call, patch
from typing import Any, Dict

from src.clients.aws_cost_usage_client import AwsCostUsageClient
from tests.clients.test_aws_cost_usage_responses import GET_USAGE_COST_SUCCESS


class TestAwsCostUsageClient(AwsScannerTestCase):
    @staticmethod
    def cost_usage_client(self) -> AwsCostUsageClient:
        return AwsCostUsageClient(Mock())

    def test_get_aws_cost_usage(self) -> None:
        client = AwsCostUsageClient(Mock())
        # result = client.get_aws_cost_usage("lambda", {"date_from": "2021-07-01", "date_to": "2021-08-01"})
        # self.assertEqual(result, {})

        with patch.object(AwsCostUsageClient, "get_aws_cost_usage") as get_cost_usage:
            client.get_aws_cost_usage("lambda", {"date_from": "2021-07-01", "date_to": "2021-08-01"})
        self.assertEqual(
            [call("lambda", {"date_from": "2021-07-01", "date_to": "2021-08-01"})], get_cost_usage.mock_calls
        )
