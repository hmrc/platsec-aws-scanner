from typing import Any, Dict

from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients.aws_athena_client import AwsAthenaClient
from src.clients.aws_athena_cloudtrail_queries import CREATE_TABLE
from src.tasks.aws_athena_task import AwsAthenaTask


class AwsCloudTrailTask(AwsAthenaTask):
    def _create_table(self, client: AwsAthenaClient) -> None:
        client.create_table(
            database=self._database,
            table=self._account.identifier,
            query_template=CREATE_TABLE,
            query_attributes={
                "account": self._account.identifier,
                "cloudtrail_logs_bucket": Config().cloudtrail_logs_bucket(),
            },
        )

    def _create_partition(self, client: AwsAthenaClient) -> None:
        client.add_partition(self._database, self._account, self._partition)

    def _run_task(self, client: AwsAthenaClient) -> Dict[Any, Any]:
        raise NotImplementedError("this is an abstract class")
