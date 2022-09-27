from pytest import raises
from unittest.mock import Mock, call

from src.clients.aws_logs_client import AwsLogsClient
from src.data.aws_scanner_exceptions import LogsException

from tests.clients import test_aws_logs_client_responses as responses
from tests.test_types_generator import client_error, tag


def test_describe_log_groups() -> None:
    boto = Mock(
        describe_log_groups=Mock(return_value=responses.DESCRIBE_LOG_GROUPS),
        describe_subscription_filters=Mock(side_effect=responses.DESCRIBE_SUBSCRIPTION_FILTERS),
        list_tags_log_group=Mock(side_effect=responses.LIST_TAGS_LOG_GROUP),
    )
    log_groups = AwsLogsClient(boto, Mock()).describe_log_groups("lg")
    boto.describe_log_groups.assert_called_once_with(logGroupNamePrefix="lg")
    boto.describe_subscription_filters.assert_has_calls([call(logGroupName="lg_1"), call(logGroupName="lg_2")])
    assert responses.EXPECTED_LOG_GROUPS == log_groups


def test_describe_log_groups_failure() -> None:
    boto = Mock(describe_log_groups=Mock(side_effect=client_error("DescribeLogGroup", "AccessDenied", "nope")))
    with raises(LogsException, match="a_log_group"):
        AwsLogsClient(boto, Mock()).describe_log_groups("a_log_group")


def test_describe_subscription_filters_failure() -> None:
    boto = Mock(
        describe_subscription_filters=Mock(
            side_effect=client_error("DescribeSubscriptionFilters", "AccessDenied", "nope")
        )
    )
    with raises(LogsException, match="a_log_group"):
        AwsLogsClient(boto, Mock()).describe_subscription_filters("a_log_group")


def test_list_tags_log_group_failure() -> None:
    boto = Mock(list_tags_log_group=Mock(side_effect=client_error("ListTagsLogGroup", "AccessDenied", "no")))
    with raises(LogsException, match="some_log_group"):
        AwsLogsClient(boto, Mock()).list_tags_log_group("some_log_group")


def test_create_log_group() -> None:
    boto = Mock()
    AwsLogsClient(boto, Mock()).create_log_group("some_log_group")
    boto.create_log_group.assert_called_once_with(logGroupName="some_log_group")


def test_create_log_group_failure() -> None:
    boto = Mock(create_log_group=Mock(side_effect=client_error("CreateLogGroup", "AccessDenied", "nope")))
    with raises(LogsException, match="a_log_group"):
        AwsLogsClient(boto, Mock()).create_log_group("a_log_group")


def test_tag_log_group() -> None:
    boto = Mock()
    AwsLogsClient(boto, Mock()).tag_log_group("lg", [tag("a", "1"), tag("b", "2")])
    boto.tag_log_group.assert_called_once_with(logGroupName="lg", tags={"a": "1", "b": "2"})


def test_tag_log_group_failure() -> None:
    boto = Mock(tag_log_group=Mock(side_effect=client_error("TagLogGroup", "AccessDenied", "stop")))
    with raises(LogsException, match="lg"):
        AwsLogsClient(boto, Mock()).tag_log_group("lg", [])


def test_put_subscription_filter() -> None:
    log_group_name = "/vpc/central_flow_log"
    filter_name = "VpcFlowLogsForward"
    filter_pattern = "[version, account_id, interface_id]"
    destination_arn = "arn:aws:logs:::destination:central"
    boto = Mock()
    AwsLogsClient(boto, Mock()).put_subscription_filter(log_group_name, filter_name, filter_pattern, destination_arn)
    boto.put_subscription_filter.assert_called_once_with(
        logGroupName=log_group_name,
        filterName=filter_name,
        filterPattern=filter_pattern,
        destinationArn=destination_arn,
    )


def test_put_subscription_filter_failure() -> None:
    boto = Mock(put_subscription_filter=Mock(side_effect=client_error("PubSubscriptionFilter", "Error", "nope")))
    with raises(LogsException, match="some_filter_name"):
        AwsLogsClient(boto, Mock()).put_subscription_filter("lg", "some_filter_name", "pattern", "dest")


def test_put_retention_policy() -> None:
    boto = Mock()
    AwsLogsClient(boto, Mock()).put_retention_policy("a_log_group", 7)
    boto.put_retention_policy.assert_called_once_with(logGroupName="a_log_group", retentionInDays=7)


def test_put_retention_policy_failure() -> None:
    boto = Mock(put_retention_policy=Mock(side_effect=client_error("PutRetentionPolicy", "Error", "boom")))
    with raises(LogsException, match="14 days retention policy for log group 'broken_log_group'"):
        AwsLogsClient(boto, Mock()).put_retention_policy("broken_log_group", 14)


def test_delete_subscription_filter() -> None:
    boto = Mock()
    AwsLogsClient(boto, Mock()).delete_subscription_filter("a_log_group", "a_filter")
    boto.delete_subscription_filter.assert_called_once_with(logGroupName="a_log_group", filterName="a_filter")


def test_delete_subscription_filter_failure() -> None:
    boto = Mock(delete_subscription_filter=Mock(side_effect=client_error("DeleteSubscriptionFilter", "No", "no!")))
    with raises(LogsException, match="some_broken_filter"):
        AwsLogsClient(boto, Mock()).delete_subscription_filter("a_log_group", "some_broken_filter")


def test_put_resource_policy() -> None:
    boto = Mock()
    AwsLogsClient(boto, Mock()).put_resource_policy(policy_name="a_policy_name", policy_document="a_policy_document")
    boto.put_resource_policy.assert_called_once_with(policyName="a_policy_name", policyDocument="a_policy_document")


def test_put_resource_policy_failure() -> None:
    boto = Mock(put_resource_policy=Mock(side_effect=client_error("PutResourcePolicy", "some_error", "boom!")))
    with raises(LogsException, match="logs resource policy"):
        AwsLogsClient(boto, Mock()).put_resource_policy("a_policy_name", "a_policy_document")
