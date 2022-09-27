from unittest.mock import Mock

from _pytest.python_api import raises

from src.clients.aws_resolver_client import AwsResolverClient, ResolverQueryLogConfigs
from src.data.aws_scanner_exceptions import LogsException
from tests.clients import test_aws_resolver_client_responses as responses
from tests.test_types_generator import client_error


def test_list_query_log_configs() -> None:
    boto = Mock(
        list_resolver_query_log_configs=Mock(return_value=responses.LIST_QUERY_LOG_CONFIGS),
    )
    query_log_configs = AwsResolverClient(boto).list_resolver_query_log_configs("log_group_arn")
    boto.list_resolver_query_log_configs.calledoncewith("log_group_arn")

    assert [
        ResolverQueryLogConfigs(name="scanner_query_log_name", arn="arn", destination_arn="log_group_arn"),
    ] == query_log_configs


def test_list_query_log_configs_failure() -> None:
    boto = Mock(
        list_resolver_query_log_configs=Mock(side_effect=client_error("SomeError", "AccessDenied", "nope")),
    )
    with raises(LogsException, match="unable to run list_resolver_query_log_configs: An error occurred"):
        AwsResolverClient(boto).list_resolver_query_log_configs("log_group_arn")
