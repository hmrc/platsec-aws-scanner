from datetime import date
from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from src.clients.aws_cost_usage_client import AwsCostUsageClient, CostUsageException
from tests.clients.test_aws_cost_usage_responses import GET_USAGE_COST_SUCCESS


class TestAwsCostUsageClient(AwsScannerTestCase):
    def test_get_aws_cost_usage_success(self) -> None:
        boto_cost_usage = Mock(get_cost_and_usage=Mock(return_value=GET_USAGE_COST_SUCCESS))
        client = AwsCostUsageClient(boto_cost_usage)

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

        self.assertEqual(client.get_aws_cost_usage("Lambda", 2021, 2), expected)

    def test_get_aws_cost_usage_failure(self) -> None:
        client = AwsCostUsageClient(Mock())
        service = "lambda"
        with self.assertRaisesRegex(CostUsageException, f"unable to get cost usage data for {service}:"):
            client.get_aws_cost_usage(service, 2022, 20)
