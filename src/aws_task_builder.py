from logging import getLogger
from typing import Any, Callable, Dict, List, Optional, Sequence, Type, Union

from src.aws_scanner_argument_parser import AwsScannerArguments
from src.aws_scanner_argument_parser import AwsScannerCommands as Cmd
from src.clients.aws_client_factory import AwsClientFactory
from src.clients.aws_organizations_client import AwsOrganizationsClient
from src.data.aws_organizations_types import Account
from src.data.aws_scanner_exceptions import UnsupportedTaskException
from src.tasks.aws_athena_cleaner_task import AwsAthenaCleanerTask
from src.tasks.aws_audit_central_logging_task import AwsAuditCentralLoggingTask
from src.tasks.aws_audit_cloudtrail_task import AwsAuditCloudtrailTask
from src.tasks.aws_audit_cost_explorer_task import AwsAuditCostExplorerTask
from src.tasks.aws_audit_iam_task import AwsAuditIamTask
from src.tasks.aws_audit_password_policy_task import AwsAuditPasswordPolicyTask
from src.tasks.aws_audit_s3_task import AwsAuditS3Task
from src.tasks.aws_audit_vpc_flow_logs_task import AwsAuditVPCFlowLogsTask
from src.tasks.aws_audit_vpc_peering_task import AwsAuditVpcPeeringTask
from src.tasks.aws_create_athena_table_task import AwsCreateAthenaTableTask
from src.tasks.aws_create_flow_logs_table_task import AwsCreateFlowLogsTableTask
from src.tasks.aws_list_accounts_task import AwsListAccountsTask
from src.tasks.aws_list_ssm_parameters_task import AwsListSSMParametersTask
from src.tasks.aws_principal_by_ip_finder_task import AwsPrincipalByIPFinderTask
from src.tasks.aws_role_usage_scanner_task import AwsRoleUsageScannerTask
from src.tasks.aws_service_usage_scanner_task import AwsServiceUsageScannerTask
from src.tasks.aws_audit_ec2_instances_task import AwsAuditEc2InstancesTask
from src.tasks.aws_task import AwsTask


class AwsTaskBuilder:
    _args: AwsScannerArguments
    _orgs: Optional[AwsOrganizationsClient]

    def __init__(self, factory: AwsClientFactory, args: AwsScannerArguments):
        self._logger = getLogger(self.__class__.__name__)
        self._args = args
        self._orgs = None if args.disable_account_lookup else factory.get_organizations_client()

    def build_tasks(self) -> Sequence[AwsTask]:
        task_mapping: Dict[str, Callable[[], Sequence[AwsTask]]] = {
            Cmd.service_usage: lambda: self._services_tasks(
                AwsServiceUsageScannerTask,
                services=self._args.services,
                partition=self._args.partition,
            ),
            Cmd.role_usage: lambda: self._tasks(
                AwsRoleUsageScannerTask, partition=self._args.partition, role=self._args.role
            ),
            Cmd.find_principal: lambda: self._tasks(
                AwsPrincipalByIPFinderTask,
                partition=self._args.partition,
                source_ip=self._args.source_ip,
            ),
            Cmd.create_table: lambda: self._tasks(AwsCreateAthenaTableTask, partition=self._args.partition),
            Cmd.list_accounts: lambda: self._standalone_task(AwsListAccountsTask),
            Cmd.list_ssm_parameters: lambda: self._tasks(AwsListSSMParametersTask),
            Cmd.drop: lambda: self._standalone_task(AwsAthenaCleanerTask),
            Cmd.audit_s3: lambda: self._tasks(AwsAuditS3Task),
            Cmd.audit_iam: lambda: self._tasks(AwsAuditIamTask),
            Cmd.cost_explorer: lambda: self._services_tasks(
                AwsAuditCostExplorerTask,
                services=self._args.services,
                year=self._args.year,
                month=self._args.month,
            ),
            Cmd.audit_vpc_flow_logs: lambda: self._tasks(
                AwsAuditVPCFlowLogsTask,
                enforce=self._args.enforce,
                with_subscription_filter=self._args.with_subscription_filter,
            ),
            Cmd.audit_password_policy: lambda: self._tasks(AwsAuditPasswordPolicyTask, enforce=self._args.enforce),
            Cmd.audit_cloudtrail: lambda: self._tasks(AwsAuditCloudtrailTask),
            Cmd.audit_central_logging: lambda: self._standalone_task(AwsAuditCentralLoggingTask),
            Cmd.create_flow_logs_table: lambda: self._standalone_task(
                AwsCreateFlowLogsTableTask, partition=self._args.partition
            ),
            Cmd.audit_vpc_peering: lambda: self._tasks(AwsAuditVpcPeeringTask),
            Cmd.audit_ec2_instances: lambda: self._tasks(AwsAuditEc2InstancesTask),
        }
        try:
            return task_mapping[self._args.task]()
        except KeyError:
            raise UnsupportedTaskException(f"task '{self._args.task}' is not supported") from None

    def _tasks(self, task_type: Type[AwsTask], **kwargs: Any) -> Sequence[AwsTask]:
        self._logger.info(f"creating {task_type.__name__} tasks with {kwargs}")
        return [task_type(account=account, **kwargs) for account in self._get_target_accounts()]

    def _services_tasks(
        self,
        task: Type[Union[AwsAuditCostExplorerTask, AwsServiceUsageScannerTask]],
        services: List[str],
        **kwargs: Any,
    ) -> Sequence[AwsTask]:
        self._logger.info(f"creating {task.__name__} tasks with {kwargs}")
        return [
            task(account=account, service=service, **kwargs)
            for account in self._get_target_accounts()
            for service in services
        ]

    def _standalone_task(self, task: Type[AwsTask], **kwargs: Any) -> Sequence[AwsTask]:
        self._logger.info(f"creating {task.__name__}")
        return [task(**kwargs)]

    def _get_target_accounts(self) -> Sequence[Account]:
        if not self._orgs:
            if not self._args.accounts:
                raise SystemExit("account lookup is disabled and no target accounts were provided")
            return [Account(acc, acc) for acc in self._args.accounts]
        return (
            self._orgs.find_account_by_ids(self._args.accounts)
            if self._args.accounts
            else self._orgs.get_target_accounts(self._args.parent)
        )
