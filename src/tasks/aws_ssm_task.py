from typing import Any, Dict

from src.tasks.aws_task import AwsTask
from src.clients.aws_ssm_client import AwsSSMClient


class AwsSSMTask(AwsTask):
    def _run_task(self, client: AwsSSMClient) -> Dict[Any, Any]:
        raise NotImplementedError("this is an abstract class")
