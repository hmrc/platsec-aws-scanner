from string import Template
from typing import Any, Dict

from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients.aws_athena_client import AwsAthenaClient
from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.data.aws_scanner_exceptions import AddPartitionException, CreateTableException
from src.tasks.aws_athena_task import AwsAthenaTask
from src.clients.aws_athena_flow_logs_queries import (
    CREATE_FL_TABLE_YEAR_MONTH,
    CREATE_FL_TABLE_YEAR_MONTH_DAY,
    ADD_PARTITION_YEAR_MONTH_DAY,
    ADD_PARTITION_YEAR_MONTH,
)


class AwsCreateFlowLogsTableTask(AwsAthenaTask):
    def __init__(self, partition: AwsAthenaDataPartition, region: str):
        self._config = Config()
        super().__init__(
            description="create Athena table for flow logs and load data partition",
            account=self._config.athena_account(),
            partition=partition,
            region=region,
        )
        self._table_name = self._generate_table_name()

    def _create_table(self, client: AwsAthenaClient) -> None:
        query_template = CREATE_FL_TABLE_YEAR_MONTH_DAY if self._partition.day else CREATE_FL_TABLE_YEAR_MONTH
        query_attributes = {
            "table_name": self._table_name,
            "flow_logs_bucket": self._config.athena_flow_logs_bucket(),
        }

        client.run_query(
            database=self._database,
            query=Template(query_template).substitute(**query_attributes),
            raise_on_failure=CreateTableException,
        ),

    def _create_partition(self, client: AwsAthenaClient) -> None:
        query_template = ADD_PARTITION_YEAR_MONTH_DAY if self._partition.day else ADD_PARTITION_YEAR_MONTH
        query_attributes = {
            "table_name": self._table_name,
            "year": self._partition.year,
            "month": self._partition.month,
            "flow_logs_bucket": Config().athena_flow_logs_bucket(),
        } | {"day": day for day in [self._partition.day] if day}

        client.run_query(
            database=self._database,
            query=Template(query_template).substitute(**query_attributes),
            raise_on_failure=AddPartitionException,
        )

    def _run_task(self, client: AwsAthenaClient) -> Dict[Any, Any]:
        return {"database": self._database, "table": self._table_name}

    def _teardown(self, client: AwsAthenaClient) -> None:
        pass

    def _generate_table_name(self) -> str:
        day_suffix = f"_{self._partition.day}" if self._partition.day else ""
        return f"flow_logs_{self._partition.year}_{self._partition.month}{day_suffix}"
