from unittest import TestCase
from unittest.mock import Mock

from src.clients.aws_athena_flow_logs_queries import (
    ADD_PARTITION_YEAR_MONTH_DAY,
    ADD_PARTITION_YEAR_MONTH,
    CREATE_TABLE_WITH_YEAR_MONTH_PARTITION,
    CREATE_TABLE_WITH_YEAR_MONTH_DAY_PARTITION,
)

from tests.test_types_generator import create_flow_logs_table_task, partition


class TestAwsCreateFlowLogsTableTask(TestCase):
    def test_create_table_for_year_month_data_partition(self) -> None:
        task = create_flow_logs_table_task(partition(year=2020, month=11))
        client = Mock()
        task._create_table(client)
        client.create_table.assert_called_once_with(
            database=task._database,
            table="flow_logs_2020_11",
            query_template=CREATE_TABLE_WITH_YEAR_MONTH_PARTITION,
            query_attributes={"table_name": "flow_logs_2020_11", "flow_logs_bucket": "the-flow-logs-bucket"},
        )

    def test_create_table_for_year_month_day_data_partition(self) -> None:
        task = create_flow_logs_table_task(partition(year=2020, month=10, day=30))
        client = Mock()
        task._create_table(client)
        client.create_table.assert_called_once_with(
            database=task._database,
            table="flow_logs_2020_10_30",
            query_template=CREATE_TABLE_WITH_YEAR_MONTH_DAY_PARTITION,
            query_attributes={"table_name": "flow_logs_2020_10_30", "flow_logs_bucket": "the-flow-logs-bucket"},
        )

    def test_create_partition_year_month(self) -> None:
        task = create_flow_logs_table_task(partition(year=2020, month=9))
        client = Mock()
        task._create_partition(client)
        client.add_partition.assert_called_once_with(
            database=task._database,
            table="flow_logs_2020_09",
            query_template=ADD_PARTITION_YEAR_MONTH,
            query_attributes={
                "table_name": "flow_logs_2020_09",
                "year": "2020",
                "month": "09",
                "flow_logs_bucket": "the-flow-logs-bucket",
            },
        )

    def test_create_partition_year_month_day(self) -> None:
        task = create_flow_logs_table_task(partition(year=2020, month=9, day=29))
        client = Mock()
        task._create_partition(client)
        client.add_partition.assert_called_once_with(
            database=task._database,
            table="flow_logs_2020_09_29",
            query_template=ADD_PARTITION_YEAR_MONTH_DAY,
            query_attributes={
                "table_name": "flow_logs_2020_09_29",
                "year": "2020",
                "month": "09",
                "day": "29",
                "flow_logs_bucket": "the-flow-logs-bucket",
            },
        )

    def test_does_not_teardown(self) -> None:
        client = Mock()
        create_flow_logs_table_task()._teardown(client)
        assert not client.mock_calls
