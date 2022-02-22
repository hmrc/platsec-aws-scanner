from unittest import TestCase
from unittest.mock import Mock

from src.clients.aws_athena_flow_logs_queries import (
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
