from typing import Any, Dict

from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients.aws_athena_client import AwsAthenaClient
from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.tasks.aws_athena_task import AwsAthenaTask
from src.clients.aws_athena_flow_logs_queries import (
    CREATE_TABLE_WITH_YEAR_MONTH_PARTITION as YEAR_MONTH,
    CREATE_TABLE_WITH_YEAR_MONTH_DAY_PARTITION as YEAR_MONTH_DAY,
)


class AwsCreateFlowLogsTableTask(AwsAthenaTask):
    def __init__(self, partition: AwsAthenaDataPartition):
        self._config = Config()
        super().__init__(
            "create Athena table for flow logs and load data partition", self._config.athena_account(), partition
        )

    def _create_table(self, client: AwsAthenaClient) -> None:
        day_suffix = f"_{self._partition.day}" if self._partition.day else ""
        table_name = f"flow_logs_{self._partition.year}_{self._partition.month}{day_suffix}"
        client.create_table(
            database=self._database,
            table=table_name,
            query_template=YEAR_MONTH_DAY if self._partition.day else YEAR_MONTH,
            query_attributes={"table_name": table_name, "flow_logs_bucket": self._config.athena_flow_logs_bucket()},
        )

    def _create_partition(self, client: AwsAthenaClient) -> None:
        """"""

    def _run_task(self, client: AwsAthenaClient) -> Dict[Any, Any]:
        """"""
