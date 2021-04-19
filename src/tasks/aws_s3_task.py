from typing import Any, Dict

from src.tasks.aws_task import AwsTask
from src.clients.aws_s3_client import AwsS3Client


class AwsS3Task(AwsTask):
    def _run_task(self, client: AwsS3Client) -> Dict[Any, Any]:
        raise NotImplementedError("this is an abstract class")
