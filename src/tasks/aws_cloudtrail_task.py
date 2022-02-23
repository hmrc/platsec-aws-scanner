from string import Template
from typing import Any, Dict

from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients.aws_athena_client import AwsAthenaClient
from src.clients.aws_athena_cloudtrail_queries import ADD_PARTITION_YEAR_MONTH, CREATE_TABLE
from src.data.aws_scanner_exceptions import AddPartitionException, CreateTableException
from src.tasks.aws_athena_task import AwsAthenaTask


class AwsCloudTrailTask(AwsAthenaTask):
    def _create_table(self, client: AwsAthenaClient) -> None:
        client.run_query(
            database=self._database,
            query=Template(CREATE_TABLE).substitute(
                account=self._account.identifier, cloudtrail_logs_bucket=Config().cloudtrail_logs_bucket()
            ),
            raise_on_failure=CreateTableException,
        )

    def _create_partition(self, client: AwsAthenaClient) -> None:
        client.run_query(
            database=self._database,
            query=Template(ADD_PARTITION_YEAR_MONTH).substitute(
                account=self._account.identifier,
                region=self._partition.region,
                year=self._partition.year,
                month=self._partition.month,
                cloudtrail_logs_bucket=Config().cloudtrail_logs_bucket(),
            ),
            raise_on_failure=AddPartitionException,
        )

    def _run_task(self, client: AwsAthenaClient) -> Dict[Any, Any]:
        raise NotImplementedError("this is an abstract class")
