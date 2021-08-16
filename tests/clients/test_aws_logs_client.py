from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, call, patch

from src.clients.aws_logs_client import AwsLogsClient
from src.data.aws_scanner_exceptions import LogsException

from tests.clients import test_aws_logs_client_responses as responses
from tests.test_types_generator import client_error, log_group, subscription_filter


class TestAwsLogsClient(AwsScannerTestCase):
    def test_provide_central_vpc_log_group(self) -> None:
        log_groups = [log_group(name="/something_else"), log_group()]
        with patch.object(AwsLogsClient, "describe_log_groups", return_value=log_groups):
            self.assertEqual(log_groups[1], AwsLogsClient(Mock()).provide_central_vpc_log_group())

    def test_provide_central_vpc_log_group_creates_if_not_exists(self) -> None:
        lg = log_group(name="the-log-group")
        with patch.object(AwsLogsClient, "describe_log_groups", return_value=[]):
            with patch.object(AwsLogsClient, "create_central_vpc_log_group", return_value=lg) as create:
                self.assertEqual(lg, AwsLogsClient(Mock()).provide_central_vpc_log_group())
        create.assert_called_once()

    def test_create_central_vpc_log_group(self) -> None:
        with patch.object(AwsLogsClient, "create_log_group") as create_log_group:
            with patch.object(AwsLogsClient, "put_subscription_filter") as put_subscription_filter:
                clg = AwsLogsClient(Mock()).create_central_vpc_log_group()
        self.assertTrue(clg.central_vpc_log_group)
        self.assertRegex(clg.name, r"/vpc/central_flow_log_\d{4}")
        self.assertRegex(create_log_group.call_args[1]["name"], clg.name)
        sub_filter = put_subscription_filter.call_args[1]["subscription_filter"]
        self.assertEqual(clg.name, sub_filter.log_group_name)
        self.assertEqual(clg.subscription_filters[0], sub_filter)

    def test_describe_log_groups(self) -> None:
        boto = Mock(
            describe_log_groups=Mock(return_value=responses.DESCRIBE_LOG_GROUPS),
            describe_subscription_filters=Mock(side_effect=responses.DESCRIBE_SUBSCRIPTION_FILTERS),
        )
        log_groups = AwsLogsClient(boto).describe_log_groups("/vpc/flow_log")
        boto.describe_log_groups.assert_called_once_with(logGroupNamePrefix="/vpc/flow_log")
        boto.describe_subscription_filters.assert_has_calls(
            [call(logGroupName="/vpc/flow_log"), call(logGroupName="/vpc/flow_log_2")]
        )
        self.assertEqual(responses.EXPECTED_LOG_GROUPS, log_groups)

    def test_describe_log_groups_failure(self) -> None:
        boto = Mock(describe_log_groups=Mock(side_effect=client_error("DescribeLogGroup", "AccessDenied", "nope")))
        with self.assertRaisesRegex(LogsException, "a_log_group"):
            AwsLogsClient(boto).describe_log_groups("a_log_group")

    def test_describe_subscription_filters_failure(self) -> None:
        boto = Mock(
            describe_subscription_filters=Mock(
                side_effect=client_error("DescribeSubscriptionFilters", "AccessDenied", "nope")
            )
        )
        with self.assertRaisesRegex(LogsException, "a_log_group"):
            AwsLogsClient(boto).describe_subscription_filters("a_log_group")

    def test_create_log_group(self) -> None:
        boto = Mock()
        AwsLogsClient(boto).create_log_group("some_log_group")
        boto.create_log_group.assert_called_once_with(logGroupName="some_log_group")

    def test_create_log_group_failure(self) -> None:
        boto = Mock(create_log_group=Mock(side_effect=client_error("CreateLogGroup", "AccessDenied", "nope")))
        with self.assertRaisesRegex(LogsException, "a_log_group"):
            AwsLogsClient(boto).create_log_group("a_log_group")

    def test_put_subscription_filter(self) -> None:
        sub_filter = subscription_filter()
        boto = Mock()
        AwsLogsClient(boto).put_subscription_filter(sub_filter)
        boto.put_subscription_filter.assert_called_once_with(
            logGroupName=sub_filter.log_group_name,
            filterName=sub_filter.filter_name,
            filterPattern=sub_filter.filter_pattern,
            destinationArn=sub_filter.destination_arn,
        )

    def test_put_subscription_filter_failure(self) -> None:
        sub_filter = subscription_filter()
        boto = Mock(put_subscription_filter=Mock(side_effect=client_error("PubSubscriptionFilter", "Error", "nope")))
        with self.assertRaisesRegex(LogsException, sub_filter.filter_name):
            AwsLogsClient(boto).put_subscription_filter(sub_filter)
