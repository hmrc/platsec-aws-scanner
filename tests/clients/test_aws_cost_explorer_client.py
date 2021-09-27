from datetime import date
from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from src.clients.aws_cost_explorer_client import AwsCostExplorerClient, CostExplorerException
from botocore.exceptions import BotoCoreError
from tests.clients.test_aws_cost_explorer_responses import GET_USAGE_COST_SUCCESS


class TestAwsCostExplorerClient(AwsScannerTestCase):
    def test_get_aws_cost_explorer_success(self) -> None:
        boto_cost_explorer = Mock(get_cost_and_usage=Mock(return_value=GET_USAGE_COST_SUCCESS))
        client = AwsCostExplorerClient(boto_cost_explorer)

        today = date.today()
        expected = {
            "Service": "Lambda",
            "DateRange": {
                "Start": "2021-02-01",
                "End": f"{today.year}-{'%02d' % today.month}-{'%02d' % today.day}",
            },
            "TotalCost:": "USD 251",
            "TotalUsage": "11800948",
        }

        self.assertEqual(client.get_aws_cost_explorer("Lambda", 2021, 2), expected)

    def test_get_aws_cost_explorer_failure(self) -> None:
        boto_cost_explorer = Mock(get_cost_and_usage=Mock(side_effect=BotoCoreError))
        client = AwsCostExplorerClient(boto_cost_explorer)

        service = "lambda"
        with self.assertRaisesRegex(CostExplorerException, f"unable to get cost usage data for {service}:"):
            client.get_aws_cost_explorer(service, 2022, 20)
