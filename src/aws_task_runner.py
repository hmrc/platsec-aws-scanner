from inspect import signature
from logging import getLogger
from typing import Any, Callable, Dict, Sequence, Type

from src.data.aws_scanner_exceptions import UnsupportedClientException
from src.data.aws_task_report import AwsTaskReport
from src.clients.aws_client_factory import AwsClientFactory
from src.tasks.aws_task import AwsTask

from src.clients.aws_athena_client import AwsAthenaClient
from src.clients.aws_cost_explorer_client import AwsCostExplorerClient
from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_audit_client import AwsIamAuditClient
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_organizations_client import AwsOrganizationsClient
from src.clients.aws_ssm_client import AwsSSMClient
from src.clients.aws_s3_client import AwsS3Client
from src.clients.aws_hosted_zones_client import AwsHostedZonesClient
from src.clients.composite.aws_central_logging_client import AwsCentralLoggingClient
from src.clients.composite.aws_cloudtrail_client import AwsCloudtrailClient
from src.clients.composite.aws_vpc_client import AwsVpcClient
from src.clients.composite.aws_vpc_peering_client import AwsVpcPeeringClient
from src.clients.composite.aws_s3_kms_client import AwsS3KmsClient
from src.clients.composite.aws_route53_client import AwsRoute53Client


class AwsTaskRunner:
    def __init__(self, client_factory: AwsClientFactory) -> None:
        self._logger = getLogger(self.__class__.__name__)
        self._client_factory = client_factory

    def run(self, tasks: Sequence[AwsTask]) -> Sequence[AwsTaskReport]:
        return self._run_tasks(tasks)

    def _run_tasks(self, tasks: Sequence[AwsTask]) -> Sequence[AwsTaskReport]:
        raise NotImplementedError("this is an abstract class")

    def _run_task(self, task: AwsTask) -> AwsTaskReport:
        client_param = signature(task._run_task).parameters.get("client")

        task_client_mapping: Dict[Type[Any], Callable[[], AwsTaskReport]] = {
            AwsAthenaClient: lambda: task.run(self._client_factory.get_athena_client()),
            AwsCentralLoggingClient: lambda: task.run(self._client_factory.get_central_logging_client()),
            AwsCloudtrailClient: lambda: task.run(self._client_factory.get_cloudtrail_client(task.account)),
            AwsCostExplorerClient: lambda: task.run(self._client_factory.get_cost_explorer_client(task.account)),
            AwsEC2Client: lambda: task.run(self._client_factory.get_ec2_client(task.account)),
            AwsIamClient: lambda: task.run(self._client_factory.get_iam_client(task.account)),
            AwsIamAuditClient: lambda: task.run(self._client_factory.get_iam_client_for_audit(task.account)),
            AwsOrganizationsClient: lambda: task.run(self._client_factory.get_organizations_client()),
            AwsSSMClient: lambda: task.run(self._client_factory.get_ssm_client(task.account)),
            AwsS3Client: lambda: task.run(self._client_factory.get_s3_client(task.account)),
            AwsHostedZonesClient: lambda: task.run(self._client_factory.get_hosted_zones_client(task.account)),
            AwsS3KmsClient: lambda: task.run(self._client_factory.get_s3_kms_client(task.account)),
            AwsVpcClient: lambda: task.run(self._client_factory.get_vpc_client(task.account)),
            AwsVpcPeeringClient: lambda: task.run(self._client_factory.get_vpc_peering_client(task.account)),
            AwsRoute53Client: lambda: task.run(self._client_factory.get_route53_client(task.account)),
        }

        if not client_param:
            raise UnsupportedClientException(f"{task} requires a client argument")
        if client_param.annotation not in task_client_mapping:
            raise UnsupportedClientException(f"client type {client_param.annotation} is not supported")

        return task_client_mapping[client_param.annotation]()
