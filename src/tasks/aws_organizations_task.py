from typing import Any, Dict

from src.tasks.aws_task import AwsTask
from src.clients.aws_organizations_client import AwsOrganizationsClient


class AwsOrganizationsTask(AwsTask):
    def _run_task(self, client: AwsOrganizationsClient) -> Dict[Any, Any]:
        raise NotImplementedError("this is an abstract class")
