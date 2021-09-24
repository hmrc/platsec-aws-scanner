from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, call, patch
from typing import Any, Dict

from src.clients.aws_cost_usage_client import AwsCostUsageClient, CostUsageException
from tests.clients.test_aws_cost_usage_responses import GET_USAGE_COST_SUCCESS


class TestAwsCostUsageClient(AwsScannerTestCase):
    def test_get_aws_cost_usage_success(self) -> None:
        client = AwsCostUsageClient(Mock())

        with patch.object(AwsCostUsageClient, "get_aws_cost_usage") as get_cost_usage:
            client.get_aws_cost_usage("lambda", 2021, 8)
        self.assertEqual([call("lambda", 2021, 8)], get_cost_usage.mock_calls)

    def test_get_aws_cost_usage_failure(self) -> None:
        client = AwsCostUsageClient(Mock())
        service = "lambda"
        with self.assertRaisesRegex(CostUsageException, f"unable to get cost usage data for {service}:"):
            client.get_aws_cost_usage(service, 2022, 20)
