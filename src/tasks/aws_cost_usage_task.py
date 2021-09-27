from typing import Any, Dict

from src.tasks.aws_task import AwsTask
from src.clients.aws_cost_usage_client import AwsCostExplorerClient


class AwsCostExplorerTask(AwsTask):
    def _run_task(self, client: AwsCostExplorerClient) -> Dict[Any, Any]:
        raise NotImplementedError("this is an abstract class")
