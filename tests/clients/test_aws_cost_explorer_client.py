from unittest.mock import Mock
from datetime import date
import pytest

from src.clients.aws_cost_explorer_client import AwsCostExplorerClient
from src.data.aws_scanner_exceptions import CostExplorerException
from botocore.exceptions import BotoCoreError
from tests.clients.test_aws_cost_explorer_responses import GET_USAGE_COST_SUCCESS


def test_get_aws_cost_explorer_empty_response() -> None:
    boto_cost_explorer = Mock(get_cost_and_usage=Mock(return_value={}))
    client = AwsCostExplorerClient(boto_cost_explorer)

    with pytest.raises(CostExplorerException, match=r".*unable to get cost usage.*"):
        client.get_aws_cost_explorer(start_date=date(2020, 2, 1), end_date=date(2020, 11, 2))


def test_get_aws_cost_explorer_success() -> None:
    boto_cost_explorer = Mock(get_cost_and_usage=Mock(return_value=GET_USAGE_COST_SUCCESS))
    client = AwsCostExplorerClient(boto_cost_explorer)

    expected = [
        {
            "service": "AWS CloudTrail",
            "region": "ap-northeast-1",
            "dateRange": {
                "start": "2020-02-01",
                "end": "2020-11-02",
            },
            "totalCost:": "USD 1",
            "totalUsage": "389",
        },
        {
            "service": "AWS CloudTrail",
            "region": "eu-west-2",
            "dateRange": {
                "start": "2020-02-01",
                "end": "2020-11-02",
            },
            "totalCost:": "USD 1",
            "totalUsage": "389",
        },
        {
            "service": "Amazon DynamoDB",
            "region": "eu-west-2",
            "dateRange": {
                "start": "2020-02-01",
                "end": "2020-11-02",
            },
            "totalCost:": "USD 2",
            "totalUsage": "778",
        },
    ]

    assert expected == client.get_aws_cost_explorer(start_date=date(2020, 2, 1), end_date=date(2020, 11, 2))

    boto_cost_explorer.get_cost_and_usage.assert_called_once_with(
        TimePeriod={"Start": "2020-02-01", "End": "2020-11-02"},
        GroupBy=[
            {"Type": "DIMENSION", "Key": "REGION"},
            {"Type": "DIMENSION", "Key": "SERVICE"},
        ],
        Granularity="MONTHLY",
        Metrics=["UsageQuantity", "AmortizedCost"],
    )


def test_get_aws_cost_explorer_failure() -> None:
    boto_cost_explorer = Mock(get_cost_and_usage=Mock(side_effect=BotoCoreError))
    client = AwsCostExplorerClient(boto_cost_explorer)

    with pytest.raises(CostExplorerException, match=r".*unable to get cost usage data.*"):
        client.get_aws_cost_explorer(start_date=date(2020, 2, 1), end_date=date(2020, 11, 2))
