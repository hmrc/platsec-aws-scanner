from logging import getLogger
from typing import Any, Callable, Dict, List, Optional, Sequence, Type

from src.aws_scanner_argument_parser import AwsScannerArguments
from src.aws_scanner_argument_parser import AwsScannerCommands as Cmd
from src.clients.aws_organizations_client import AwsOrganizationsClient
from src.data.aws_organizations_types import Account
from src.tasks.aws_athena_cleaner_task import AwsAthenaCleanerTask
from src.tasks.aws_audit_s3_task import AwsAuditS3Task
from src.tasks.aws_audit_vpc_flow_logs_task import AwsAuditVPCFlowLogsTask
from src.tasks.aws_create_athena_table_task import AwsCreateAthenaTableTask
from src.tasks.aws_list_accounts_task import AwsListAccountsTask
from src.tasks.aws_list_ssm_parameters_task import AwsListSSMParametersTask
from src.tasks.aws_principal_by_ip_finder_task import AwsPrincipalByIPFinderTask
from src.tasks.aws_role_usage_scanner_task import AwsRoleUsageScannerTask
from src.tasks.aws_service_usage_scanner_task import AwsServiceUsageScannerTask
from src.tasks.aws_audit_cost_explorer_task import AwsAuditCostExplorerTask
from src.tasks.aws_task import AwsTask


class AwsTaskBuilder:
    def __init__(self, orgs: AwsOrganizationsClient):
        self._logger = getLogger(self.__class__.__name__)
        self._orgs = orgs

    def build_tasks(self, args: AwsScannerArguments) -> Sequence[AwsTask]:
        task_mapping: Dict[str, Callable[[], Sequence[AwsTask]]] = {
            Cmd.service_usage: lambda: self._tasks(
                AwsServiceUsageScannerTask, args.accounts, partition=args.partition, service=args.service
            ),
            Cmd.role_usage: lambda: self._tasks(
                AwsRoleUsageScannerTask, args.accounts, partition=args.partition, role=args.role
            ),
            Cmd.find_principal: lambda: self._tasks(
                AwsPrincipalByIPFinderTask, args.accounts, partition=args.partition, source_ip=args.source_ip
            ),
            Cmd.create_table: lambda: self._tasks(AwsCreateAthenaTableTask, args.accounts, partition=args.partition),
            Cmd.list_accounts: lambda: self._standalone_task(AwsListAccountsTask),
            Cmd.list_ssm_parameters: lambda: self._tasks(AwsListSSMParametersTask, args.accounts),
            Cmd.drop: lambda: self._standalone_task(AwsAthenaCleanerTask),
            Cmd.audit_s3: lambda: self._tasks(AwsAuditS3Task, args.accounts),
            Cmd.cost_explorer: lambda: self._tasks(
                AwsAuditCostExplorerTask, args.accounts, service=args.service, year=args.year, month=args.month
            ),
            Cmd.audit_vpc_flow_logs: lambda: self._tasks(AwsAuditVPCFlowLogsTask, args.accounts, enforce=args.enforce),
        }
        return task_mapping[args.task]()

    def _tasks(self, task: Type[AwsTask], accounts: Optional[List[str]], **kwargs: Any) -> Sequence[AwsTask]:
        self._logger.info(f"creating {task.__name__} tasks with {kwargs}")
        return [task(account=account, **kwargs) for account in self._get_target_accounts(accounts)]

    def _standalone_task(self, task: Type[AwsTask], **kwargs: Any) -> Sequence[AwsTask]:
        self._logger.info(f"creating {task.__name__}")
        return [task(**kwargs)]

    def _get_target_accounts(self, accounts: Optional[List[str]]) -> Sequence[Account]:
        return self._orgs.find_account_by_ids(accounts) if accounts else self._orgs.get_target_accounts()
