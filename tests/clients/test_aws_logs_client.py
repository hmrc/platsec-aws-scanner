from pytest import raises
from unittest.mock import Mock, call

from src.data.aws_common_types import Tag
from src.clients.aws_logs_client import AwsLogsClient
from src.data.aws_scanner_exceptions import LogsException

from tests.clients import test_aws_logs_client_responses as responses
from tests.test_types_generator import account, client_error, tag, key, subscription_filter, log_group


def test_find_log_group() -> None:
    boto_logs = Mock(
        describe_log_groups=Mock(return_value=responses.DESCRIBE_LOG_GROUPS_SINGLE_WITH_KMS),
        describe_subscription_filters=Mock(side_effect=responses.DESCRIBE_SUBSCRIPTION_FILTERS_SINGLE),
        list_tags_log_group=Mock(side_effect=responses.LIST_TAGS_LOG_GROUP),
    )

    expected_key = key(id="9")
    mock_kms = Mock(get_key=Mock(return_value=expected_key))

    actual_log_group = AwsLogsClient(boto_logs, mock_kms, account()).find_log_group("lg_2")

    boto_logs.describe_log_groups.assert_called_once_with(logGroupNamePrefix="lg_2")
    boto_logs.describe_subscription_filters.assert_has_calls([call(logGroupName="lg_2")])
    mock_kms.get_key.assert_has_calls([call("9")])
    assert actual_log_group == log_group(
        name="lg_2",
        arn="some-arn2",
        kms_key_id=expected_key.id,
        kms_key=expected_key,
        retention_days=None,
        stored_bytes=1234,
        subscription_filters=[
            subscription_filter(
                filter_name="SecondFilter",
                log_group_name="/vpc/flow_log_2",
                filter_pattern="[account_id]",
                destination_arn="arn:aws:logs:us-east-1:223322332233:destination:OtherDestination",
            )
        ],
        tags=[Tag(key="a_tag", value="a_value"), Tag(key="another_tag", value="another_value")],
    )


def test_describe_log_groups() -> None:
    boto = Mock(
        describe_log_groups=Mock(return_value=responses.DESCRIBE_LOG_GROUPS),
        describe_subscription_filters=Mock(side_effect=responses.DESCRIBE_SUBSCRIPTION_FILTERS),
        list_tags_log_group=Mock(side_effect=responses.LIST_TAGS_LOG_GROUP),
    )
    log_groups = AwsLogsClient(boto, Mock(), account()).describe_log_groups("lg")
    boto.describe_log_groups.assert_called_once_with(logGroupNamePrefix="lg")
    boto.describe_subscription_filters.assert_has_calls([call(logGroupName="lg_1"), call(logGroupName="lg_2")])
    assert responses.EXPECTED_LOG_GROUPS == log_groups


def test_describe_log_groups_failure() -> None:
    boto = Mock(describe_log_groups=Mock(side_effect=client_error("DescribeLogGroup", "AccessDenied", "nope")))
    with raises(LogsException, match="a_log_group"):
        AwsLogsClient(boto, Mock(), account()).describe_log_groups("a_log_group")


def test_describe_subscription_filters_failure() -> None:
    boto = Mock(
        describe_subscription_filters=Mock(
            side_effect=client_error("DescribeSubscriptionFilters", "AccessDenied", "nope")
        )
    )
    with raises(LogsException, match="a_log_group"):
        AwsLogsClient(boto, Mock(), account()).describe_subscription_filters("a_log_group")


def test_list_tags_log_group_failure() -> None:
    boto = Mock(list_tags_log_group=Mock(side_effect=client_error("ListTagsLogGroup", "AccessDenied", "no")))
    with raises(LogsException, match="some_log_group"):
        AwsLogsClient(boto, Mock(), account()).list_tags_log_group("some_log_group")


def test_create_log_group() -> None:
    boto = Mock()
    AwsLogsClient(boto, Mock(), account()).create_log_group("some_log_group")
    boto.create_log_group.assert_called_once_with(logGroupName="some_log_group")


def test_create_log_group_failure() -> None:
    boto = Mock(create_log_group=Mock(side_effect=client_error("CreateLogGroup", "AccessDenied", "nope")))
    with raises(LogsException, match="a_log_group"):
        AwsLogsClient(boto, Mock(), account()).create_log_group("a_log_group")


def test_tag_log_group() -> None:
    boto = Mock()
    AwsLogsClient(boto, Mock(), account()).tag_log_group("lg", [tag("a", "1"), tag("b", "2")])
    boto.tag_log_group.assert_called_once_with(logGroupName="lg", tags={"a": "1", "b": "2"})


def test_tag_log_group_failure() -> None:
    boto = Mock(tag_log_group=Mock(side_effect=client_error("TagLogGroup", "AccessDenied", "stop")))
    with raises(LogsException, match="lg"):
        AwsLogsClient(boto, Mock(), account()).tag_log_group("lg", [])


def test_put_subscription_filter() -> None:
    log_group_name = "/vpc/central_flow_log"
    filter_name = "VpcFlowLogsForward"
    filter_pattern = "[version, account_id, interface_id]"
    destination_arn = "arn:aws:logs:some-test-aws-region:555666777888:destination:central"
    boto = Mock()
    AwsLogsClient(boto, Mock(), account()).put_subscription_filter(
        log_group_name, filter_name, filter_pattern, destination_arn
    )
    boto.put_subscription_filter.assert_called_once_with(
        logGroupName=log_group_name,
        filterName=filter_name,
        filterPattern=filter_pattern,
        destinationArn=destination_arn,
    )


def test_put_subscription_filter_failure() -> None:
    boto = Mock(put_subscription_filter=Mock(side_effect=client_error("PubSubscriptionFilter", "Error", "nope")))
    with raises(LogsException, match="some_filter_name"):
        AwsLogsClient(boto, Mock(), account()).put_subscription_filter("lg", "some_filter_name", "pattern", "dest")


def test_put_retention_policy() -> None:
    boto = Mock()
    AwsLogsClient(boto, Mock(), account()).put_retention_policy("a_log_group", 7)
    boto.put_retention_policy.assert_called_once_with(logGroupName="a_log_group", retentionInDays=7)


def test_put_retention_policy_failure() -> None:
    boto = Mock(put_retention_policy=Mock(side_effect=client_error("PutRetentionPolicy", "Error", "boom")))
    with raises(LogsException, match="14 days retention policy for log group 'broken_log_group'"):
        AwsLogsClient(boto, Mock(), account()).put_retention_policy("broken_log_group", 14)


def test_delete_subscription_filter() -> None:
    boto = Mock()
    AwsLogsClient(boto, Mock(), account()).delete_subscription_filter("a_log_group", "a_filter")
    boto.delete_subscription_filter.assert_called_once_with(logGroupName="a_log_group", filterName="a_filter")


def test_delete_subscription_filter_failure() -> None:
    boto = Mock(delete_subscription_filter=Mock(side_effect=client_error("DeleteSubscriptionFilter", "No", "no!")))
    with raises(LogsException, match="some_broken_filter"):
        AwsLogsClient(boto, Mock(), account()).delete_subscription_filter("a_log_group", "some_broken_filter")


def test_put_resource_policy() -> None:
    boto = Mock()
    AwsLogsClient(boto, Mock(), account()).put_resource_policy(
        policy_name="a_policy_name", policy_document={"a_policy_document": 1}
    )
    boto.put_resource_policy.assert_called_once_with(
        policyName="a_policy_name", policyDocument='{"a_policy_document": 1}'
    )


def test_put_resource_policy_failure() -> None:
    boto = Mock(put_resource_policy=Mock(side_effect=client_error("PutResourcePolicy", "some_error", "boom!")))
    with raises(LogsException, match="logs resource policy"):
        AwsLogsClient(boto, Mock(), account()).put_resource_policy("a_policy_name", {"a_policy_document": 1})


def test_get_resource_policy() -> None:
    boto = Mock(describe_resource_policies=Mock(return_value=responses.DESCRIBE_RESOURCE_POLICIES))
    response = AwsLogsClient(boto, Mock(), account()).get_resource_policy(policy_name="a_policy_name")

    boto.describe_resource_policies.assert_called_once()

    assert response == {"text": "my favorite policy statement"}


def test_get_resource_policy_returns_none_when_not_found() -> None:
    boto = Mock(describe_resource_policies=Mock(return_value=responses.DESCRIBE_RESOURCE_POLICIES))
    response = AwsLogsClient(boto, Mock(), account()).get_resource_policy(policy_name="you will never find this policy")

    boto.describe_resource_policies.assert_called_once()

    assert response is None


def test_get_resource_policy_returns_none_when_no_policy_returned() -> None:
    boto = Mock(describe_resource_policies=Mock(return_value=responses.DESCRIBE_RESOURCE_POLICIES_NONE))
    response = AwsLogsClient(boto, Mock(), account()).get_resource_policy(policy_name="you will never find this policy")

    boto.describe_resource_policies.assert_called_once()

    assert response is None


def test_get_resource_policy_failure() -> None:
    boto = Mock(
        describe_resource_policies=Mock(side_effect=client_error("DESCRIBE_RESOURCE_POLICIES_ERROR", "Error", "nope"))
    )
    with raises(LogsException, match="unable to describe_resource_policies"):
        AwsLogsClient(boto, Mock(), account()).get_resource_policy(policy_name="you will never find this policy")
