from typing import Any, Dict

from src.tasks.aws_task import AwsTask
from src.clients.aws_cost_usage_client import AwsCostUsageClient


class AwsCostUsageTask(AwsTask):
    def _run_task(self, client: AwsCostUsageClient) -> Dict[Any, Any]:
        raise NotImplementedError("this is an abstract class")
