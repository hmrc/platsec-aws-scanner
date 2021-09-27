from logging import getLogger
from typing import Sequence

from src.data.aws_scanner_exceptions import UnsupportedTaskException
from src.data.aws_task_report import AwsTaskReport
from src.clients.aws_client_factory import AwsClientFactory
from src.tasks.aws_athena_task import AwsAthenaTask
from src.tasks.aws_cost_usage_task import AwsCostExplorerTask
from src.tasks.aws_organizations_task import AwsOrganizationsTask
from src.tasks.aws_ssm_task import AwsSSMTask
from src.tasks.aws_s3_task import AwsS3Task
from src.tasks.aws_task import AwsTask
from src.tasks.aws_vpc_task import AwsVpcTask


class AwsTaskRunner:
    def __init__(self, client_factory: AwsClientFactory) -> None:
        self._logger = getLogger(self.__class__.__name__)
        self._client_factory = client_factory

    def run(self, tasks: Sequence[AwsTask]) -> Sequence[AwsTaskReport]:
        return self._run_tasks(tasks)

    def _run_tasks(self, tasks: Sequence[AwsTask]) -> Sequence[AwsTaskReport]:
        raise NotImplementedError("this is an abstract class")

    def _run_task(self, task: AwsTask) -> AwsTaskReport:
        if isinstance(task, AwsAthenaTask):
            return task.run(self._client_factory.get_athena_client())
        elif isinstance(task, AwsCostExplorerTask):
            return task.run(self._client_factory.get_cost_usage_client(task.account))
        elif isinstance(task, AwsOrganizationsTask):
            return task.run(self._client_factory.get_organizations_client())
        elif isinstance(task, AwsSSMTask):
            return task.run(self._client_factory.get_ssm_client(task.account))
        elif isinstance(task, AwsS3Task):
            return task.run(self._client_factory.get_s3_client(task.account))
        elif isinstance(task, AwsVpcTask):
            return task.run(self._client_factory.get_vpc_client(task.account))
        raise UnsupportedTaskException(task)
