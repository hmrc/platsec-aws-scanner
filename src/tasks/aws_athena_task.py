from typing import Any, Dict

from src.clients.aws_athena_client import AwsAthenaClient
from src.tasks.aws_task import AwsTask


class AwsAthenaTask(AwsTask):
    def _run_task(self, client: AwsAthenaClient) -> Dict[Any, Any]:
        raise NotImplementedError("this is an abstract class")
