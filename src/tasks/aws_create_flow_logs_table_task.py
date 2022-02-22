from typing import Any, Dict

from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients.aws_athena_client import AwsAthenaClient
from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.tasks.aws_athena_task import AwsAthenaTask
from src.clients.aws_athena_flow_logs_queries import (
    CREATE_TABLE_WITH_YEAR_MONTH_PARTITION as YEAR_MONTH_TABLE,
    CREATE_TABLE_WITH_YEAR_MONTH_DAY_PARTITION as YEAR_MONTH_DAY_TABLE,
    ADD_PARTITION_YEAR_MONTH_DAY as YEAR_MONTH_DAY_PARTITION,
    ADD_PARTITION_YEAR_MONTH as YEAR_MONTH_PARTITION,
)


class AwsCreateFlowLogsTableTask(AwsAthenaTask):
    def __init__(self, partition: AwsAthenaDataPartition):
        self._config = Config()
        super().__init__(
            "create Athena table for flow logs and load data partition", self._config.athena_account(), partition
        )

    def _create_table(self, client: AwsAthenaClient) -> None:
        client.create_table(
            database=self._database,
            table=self._generate_table_name(),
            query_template=YEAR_MONTH_DAY_TABLE if self._partition.day else YEAR_MONTH_TABLE,
            query_attributes={
                "table_name": self._generate_table_name(),
                "flow_logs_bucket": self._config.athena_flow_logs_bucket(),
            },
        )

    def _create_partition(self, client: AwsAthenaClient) -> None:
        client.add_partition(
            database=self._database,
            table=self._generate_table_name(),
            query_template=YEAR_MONTH_DAY_PARTITION if self._partition.day else YEAR_MONTH_PARTITION,
            query_attributes={
                "table_name": self._generate_table_name(),
                "year": self._partition.year,
                "month": self._partition.month,
                "flow_logs_bucket": Config().athena_flow_logs_bucket(),
            }
            | {"day": day for day in [self._partition.day] if day},
        )

    def _run_task(self, client: AwsAthenaClient) -> Dict[Any, Any]:
        """"""

    def _teardown(self, client: AwsAthenaClient) -> None:
        pass

    def _generate_table_name(self) -> str:
        day_suffix = f"_{self._partition.day}" if self._partition.day else ""
        return f"flow_logs_{self._partition.year}_{self._partition.month}{day_suffix}"
