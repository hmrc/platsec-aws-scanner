from unittest import TestCase
from unittest.mock import Mock

from src.clients.aws_athena_client import AwsAthenaClient
from src.data.aws_scanner_exceptions import AddPartitionException, CreateTableException

from tests.clients.test_aws_athena_flow_logs_queries import (
    ADD_PARTITION_YEAR_MONTH_DAY,
    ADD_PARTITION_YEAR_MONTH,
    CREATE_TABLE_WITH_YEAR_MONTH_PARTITION,
    CREATE_TABLE_WITH_YEAR_MONTH_DAY_PARTITION,
)

from tests.test_types_generator import create_flow_logs_table_task, partition


class TestAwsCreateFlowLogsTableTask(TestCase):
    def test_create_table_for_year_month_data_partition(self) -> None:
        task = create_flow_logs_table_task(partition(year=2020, month=11))
        client = Mock(spec=AwsAthenaClient)
        task._create_table(client)
        client.run_query.assert_called_once_with(
            database=task._database,
            query=CREATE_TABLE_WITH_YEAR_MONTH_PARTITION,
            raise_on_failure=CreateTableException,
        )

    def test_create_table_for_year_month_day_data_partition(self) -> None:
        task = create_flow_logs_table_task(partition(year=2020, month=10, day=30))
        client = Mock(spec=AwsAthenaClient)
        task._create_table(client)
        client.run_query.assert_called_once_with(
            database=task._database,
            query=CREATE_TABLE_WITH_YEAR_MONTH_DAY_PARTITION,
            raise_on_failure=CreateTableException,
        )

    def test_create_partition_year_month(self) -> None:
        task = create_flow_logs_table_task(partition(year=2020, month=9))
        client = Mock(spec=AwsAthenaClient)
        task._create_partition(client)
        client.run_query.assert_called_once_with(
            database=task._database,
            query=ADD_PARTITION_YEAR_MONTH,
            raise_on_failure=AddPartitionException,
        )

    def test_create_partition_year_month_day(self) -> None:
        task = create_flow_logs_table_task(partition(year=2020, month=9, day=29))
        client = Mock(spec=AwsAthenaClient)
        task._create_partition(client)
        client.run_query.assert_called_once_with(
            database=task._database,
            query=ADD_PARTITION_YEAR_MONTH_DAY,
            raise_on_failure=AddPartitionException,
        )

    def test_does_not_teardown(self) -> None:
        client = Mock(spec=AwsAthenaClient)
        create_flow_logs_table_task()._teardown(client)
        assert not client.mock_calls

    def test_run_task_returns_athena_metadata(self) -> None:
        client = Mock(spec=AwsAthenaClient)
        task = create_flow_logs_table_task(partition(year=2020, month=10))
        assert {"database": task._database, "table": "flow_logs_2020_10"} == task._run_task(client)
        assert not client.mock_calls
