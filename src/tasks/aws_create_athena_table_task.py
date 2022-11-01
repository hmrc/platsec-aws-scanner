from typing import Any, Dict

from src.clients.aws_athena_client import AwsAthenaClient
from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.tasks.aws_cloudtrail_task import AwsCloudTrailTask
from src.data.aws_organizations_types import Account


class AwsCreateAthenaTableTask(AwsCloudTrailTask):
    def __init__(self, account: Account, partition: AwsAthenaDataPartition, region: str):
        super().__init__(
            description="create Athena table and load data partition",
            account=account,
            partition=partition,
            region=region,
        )

    def _run_task(self, client: AwsAthenaClient) -> Dict[Any, Any]:
        return {"database": self._database, "table": self._account.identifier}

    def _teardown(self, client: AwsAthenaClient) -> None:
        pass
