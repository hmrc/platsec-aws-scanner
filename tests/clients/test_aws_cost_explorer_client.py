from unittest import TestCase
from unittest.mock import Mock

from src.clients.aws_cost_explorer_client import AwsCostExplorerClient
from src.data.aws_scanner_exceptions import CostExplorerException
from botocore.exceptions import BotoCoreError
from tests.clients.test_aws_cost_explorer_responses import GET_USAGE_COST_SUCCESS


class TestAwsCostExplorerClient(TestCase):
    def test_get_aws_cost_explorer_empty_response(self) -> None:
        boto_cost_explorer = Mock(get_cost_and_usage=Mock(return_value={}))
        client = AwsCostExplorerClient(boto_cost_explorer)

        service = "lambda"
        with self.assertRaisesRegex(CostExplorerException, f"unable to get cost usage data for {service}"):
            client.get_aws_cost_explorer(service, 2021, 8)

    def test_get_aws_cost_explorer_success(self) -> None:
        boto_cost_explorer = Mock(get_cost_and_usage=Mock(return_value=GET_USAGE_COST_SUCCESS))
        client = AwsCostExplorerClient(boto_cost_explorer)

        expected = {
            "service": "a_service",
            "dateRange": {
                "start": "2020-02-01",
                "end": f"2020-{'%02d' % 11}-{'%02d' % 2}",
            },
            "totalCost:": "USD 251",
            "totalUsage": "11800948",
        }

        self.assertEqual(expected, client.get_aws_cost_explorer("a_service", 2020, 2))

        boto_cost_explorer.get_cost_and_usage.assert_called_once_with(
            TimePeriod={"Start": "2020-02-01", "End": "2020-11-02"},
            Filter={"Dimensions": {"Key": "SERVICE", "Values": ["a_service"], "MatchOptions": ["EQUALS"]}},
            Granularity="MONTHLY",
            Metrics=["UsageQuantity", "AmortizedCost"],
        )

    def test_get_aws_cost_explorer_failure(self) -> None:
        boto_cost_explorer = Mock(get_cost_and_usage=Mock(side_effect=BotoCoreError))
        client = AwsCostExplorerClient(boto_cost_explorer)

        service = "lambda"
        with self.assertRaisesRegex(CostExplorerException, f"unable to get cost usage data for {service}:"):
            client.get_aws_cost_explorer(service, 2022, 20)
