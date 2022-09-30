from unittest.mock import Mock

from _pytest.python_api import raises

from src.clients.aws_resolver_client import AwsResolverClient, ResolverQueryLogConfig
from src.data.aws_scanner_exceptions import LogsException
from tests.clients import test_aws_resolver_client_responses as responses
from tests.test_types_generator import client_error, tag


def test_list_query_log_configs() -> None:
    boto = Mock(
        list_resolver_query_log_configs=Mock(return_value=responses.LIST_QUERY_LOG_CONFIGS),
    )

    query_log_configs = AwsResolverClient(boto).list_resolver_query_log_configs(
        query_log_config_name="query_log_config_name"
    )
    boto.list_resolver_query_log_configs.assert_called_once()
    id = "someid"

    assert [
        ResolverQueryLogConfig(
            name="scanner_query_log_name", id=id, arn="somearn", destination_arn="some_destination_arn"
        ),
        ResolverQueryLogConfig(
            name="scanner_query_log_name2", id=id, arn="somearn2", destination_arn="some_destination_arn2"
        ),
    ] == query_log_configs


def test_list_query_log_configs_failure() -> None:
    boto = Mock(
        list_resolver_query_log_configs=Mock(side_effect=client_error("SomeError", "AccessDenied", "nope")),
    )
    with raises(LogsException, match="unable to run list_resolver_query_log_configs: An error occurred"):

        AwsResolverClient(boto).list_resolver_query_log_configs(query_log_config_name="query_log_config_name")


def test_create_query_log_configs() -> None:
    dest_arn = "some_destination_arn"
    name = "scanner_query_log_name"
    id = "someid"
    boto = Mock(
        create_resolver_query_log_config=Mock(return_value=responses.CREATE_QUERY_LOG_CONFIG),
    )

    tags = [tag("foo", "bar")]
    query_log_config = AwsResolverClient(boto).create_resolver_query_log_config(
        name=name, destination_arn=dest_arn, tags=tags
    )

    boto.create_resolver_query_log_config.assert_called_once_with(
        Name=name, DestinationArn=dest_arn, Tags=[{"Key": "foo", "Value": "bar"}]
    )
    assert (
        ResolverQueryLogConfig(name=name, id=id, arn="some arn that you can use later", destination_arn=dest_arn)
        == query_log_config
    )


def test_create_query_log_configs_failure() -> None:
    boto = Mock(
        create_resolver_query_log_config=Mock(side_effect=client_error("SomeError", "AccessDenied", "nope")),
    )
    with raises(
        LogsException, match="unable to create_resolver_query_log_config with name 'fail1' and destination_arn 'fail2'"
    ):
        AwsResolverClient(boto).create_resolver_query_log_config(
            name="fail1", destination_arn="fail2", tags=[tag("foo", "bar")]
        )


def test_delete_query_log_configs() -> None:
    id = "someid"
    boto = Mock(
        delete_resolver_query_log_config=Mock(),
    )

    AwsResolverClient(boto).delete_resolver_query_log_config(id=id)

    boto.delete_resolver_query_log_config.assert_called_once_with(ResolverQueryLogConfigId=id)


def test_delete_query_log_configs_failure() -> None:
    id = "someid"
    boto = Mock(
        delete_resolver_query_log_config=Mock(side_effect=client_error("SomeError", "AccessDenied", "nope")),
    )
    with raises(LogsException, match="unable to delete_resolver_query_log_config with id 'someid'"):
        AwsResolverClient(boto).delete_resolver_query_log_config(id=id)


def test_associate_resolver_query_log_config() -> None:
    id = "someid"
    resource_id = "resource_id"
    boto = Mock(
        associate_resolver_query_log_config=Mock(),
    )

    AwsResolverClient(boto).associate_resolver_query_log_config(
        resolver_query_log_config_id=id, resource_id=resource_id
    )

    boto.associate_resolver_query_log_config.assert_called_once_with(
        ResolverQueryLogConfigId=id, ResourceId=resource_id
    )


def test_associate_resolver_query_log_config_failure() -> None:
    id = "someid"
    resource_id = "resource_id"
    boto = Mock(
        associate_resolver_query_log_config=Mock(side_effect=client_error("SomeError", "AccessDenied", "nope")),
    )
    with raises(LogsException, match="unable to associate_resolver_query_log_config with from 'someid'"):
        AwsResolverClient(boto).associate_resolver_query_log_config(
            resolver_query_log_config_id=id, resource_id=resource_id
        )


def test_disassociate_resolver_query_log_config() -> None:
    id = "someid"
    resource_id = "resource_id"
    boto = Mock(
        associate_resolver_query_log_config=Mock(),
    )

    AwsResolverClient(boto).disassociate_resolver_query_log_config(
        resolver_query_log_config_id=id, resource_id=resource_id
    )

    boto.disassociate_resolver_query_log_config.assert_called_once_with(
        ResolverQueryLogConfigId=id, ResourceId=resource_id
    )


def test_disassociate_resolver_query_log_config_failure() -> None:
    id = "someid"
    resource_id = "resource_id"
    boto = Mock(
        disassociate_resolver_query_log_config=Mock(side_effect=client_error("SomeError", "AccessDenied", "nope")),
    )
    with raises(LogsException, match="unable to disassociate_resolver_query_log_config with from 'someid'"):
        AwsResolverClient(boto).disassociate_resolver_query_log_config(
            resolver_query_log_config_id=id, resource_id=resource_id
        )


def test_query_log_config_association_exists() -> None:
    boto = Mock(
        list_resolver_query_log_config_associations=Mock(
            return_value=responses.LIST_RESOLVER_QUERY_LOG_CONFIG_ASSOCIATIONS
        ),
    )

    assert AwsResolverClient(boto).query_log_config_association_exists(
        resolver_query_log_config_id="resolver_query_log_config_id", vpc_id="vpc-id"
    )
    boto.list_resolver_query_log_config_associations.assert_called_once_with(
        Filters=[
            {"Name": "ResolverQueryLogConfigId", "Values": ["resolver_query_log_config_id"]},
            {"Name": "ResourceId", "Values": ["vpc-id"]},
        ]
    )


def test_query_log_config_association_exists_returns_false_when_not_found() -> None:
    boto = Mock(
        list_resolver_query_log_config_associations=Mock(
            return_value=responses.LIST_RESOLVER_QUERY_LOG_CONFIG_ASSOCIATIONS_NO_RESULTS
        ),
    )

    assert not AwsResolverClient(boto).query_log_config_association_exists(
        resolver_query_log_config_id="resolver_query_log_config_id", vpc_id="vpc-id"
    )
    boto.list_resolver_query_log_config_associations.assert_called_once_with(
        Filters=[
            {"Name": "ResolverQueryLogConfigId", "Values": ["resolver_query_log_config_id"]},
            {"Name": "ResourceId", "Values": ["vpc-id"]},
        ]
    )


def test_test_query_log_config_association_exists_failure() -> None:
    config_id = "someid"
    vpc_id = "resource_id"
    boto = Mock(
        list_resolver_query_log_config_associations=Mock(side_effect=client_error("SomeError", "AccessDenied", "nope")),
    )
    with raises(
        LogsException,
        match="unable to list_resolver_query_log_config_associations with config id 'someid' and vpc id resource_id",
    ):
        AwsResolverClient(boto).query_log_config_association_exists(
            resolver_query_log_config_id=config_id, vpc_id=vpc_id
        )
