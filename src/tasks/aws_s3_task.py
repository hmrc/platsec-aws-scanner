from typing import Any, Dict

from src.tasks.aws_task import AwsTask
from src.clients.composite.aws_s3_kms_client import AwsS3KmsClient


class AwsS3Task(AwsTask):
    def _run_task(self, client: AwsS3KmsClient) -> Dict[Any, Any]:
        raise NotImplementedError("this is an abstract class")
