from typing import Any, Dict

from src.clients.aws_athena_client import AwsAthenaClient
from src.tasks.aws_athena_task import AwsAthenaTask


class AwsCloudTrailTask(AwsAthenaTask):
    def _create_table(self, client: AwsAthenaClient) -> None:
        client.create_table(self._database, self._account)

    def _create_partition(self, client: AwsAthenaClient) -> None:
        client.add_partition(self._database, self._account, self._partition)

    def _run_task(self, client: AwsAthenaClient) -> Dict[Any, Any]:
        raise NotImplementedError("this is an abstract class")
