from logging import getLogger
from typing import List, Optional, Sequence

from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.clients.aws_organizations_client import AwsOrganizationsClient
from src.data.aws_organizations_types import Account
from src.tasks.aws_athena_cleaner_task import AwsAthenaCleanerTask
from src.tasks.aws_audit_s3_task import AwsAuditS3Task
from src.tasks.aws_create_athena_table_task import AwsCreateAthenaTableTask
from src.tasks.aws_list_accounts_task import AwsListAccountsTask
from src.tasks.aws_list_ssm_parameters_task import AwsListSSMParametersTask
from src.tasks.aws_principal_by_ip_finder_task import AwsPrincipalByIPFinderTask
from src.tasks.aws_role_usage_scanner_task import AwsRoleUsageScannerTask
from src.tasks.aws_service_usage_scanner_task import AwsServiceUsageScannerTask


class AwsTaskBuilder:
    def __init__(self, orgs: AwsOrganizationsClient, accounts: Optional[List[str]] = None):
        self._logger = getLogger(self.__class__.__name__)
        self._orgs = orgs
        self._accounts = accounts

    def principal_by_ip_finder_tasks(
        self, year: int, month: int, source_ip: str
    ) -> Sequence[AwsPrincipalByIPFinderTask]:
        self._logger.info(f"creating 'principal by ip finder' tasks for ip {source_ip}")
        return [
            AwsPrincipalByIPFinderTask(account, AwsAthenaDataPartition(year, month), source_ip)
            for account in self._get_target_accounts()
        ]

    def service_usage_scanner_tasks(self, year: int, month: int, service: str) -> Sequence[AwsServiceUsageScannerTask]:
        self._logger.info(f"creating 'service usage scanner' tasks for service {service}")
        return [
            AwsServiceUsageScannerTask(account, AwsAthenaDataPartition(year, month), service)
            for account in self._get_target_accounts()
        ]

    def role_usage_scanner_tasks(self, year: int, month: int, role: str) -> Sequence[AwsRoleUsageScannerTask]:
        self._logger.info(f"creating 'role usage scanner' tasks for role {role}")
        return [
            AwsRoleUsageScannerTask(account, AwsAthenaDataPartition(year, month), role)
            for account in self._get_target_accounts()
        ]

    def create_athena_table_tasks(self, year: int, month: int) -> Sequence[AwsCreateAthenaTableTask]:
        self._logger.info("creating 'create Athena table' tasks")
        return [
            AwsCreateAthenaTableTask(account, AwsAthenaDataPartition(year, month))
            for account in self._get_target_accounts()
        ]

    def clean_athena_tasks(self) -> Sequence[AwsAthenaCleanerTask]:
        self._logger.info("creating 'clean Athena' tasks")
        return [AwsAthenaCleanerTask()]

    def list_accounts_tasks(self) -> Sequence[AwsListAccountsTask]:
        self._logger.info("creating 'list organization accounts' tasks")
        return [AwsListAccountsTask()]

    def list_ssm_parameters_tasks(self) -> Sequence[AwsListSSMParametersTask]:
        self._logger.info("creating 'list SSM parameters' tasks")
        return [AwsListSSMParametersTask(account) for account in self._get_target_accounts()]

    def audit_s3_tasks(self) -> Sequence[AwsAuditS3Task]:
        self._logger.info("creating 'audit S3' tasks")
        return [AwsAuditS3Task(account) for account in self._get_target_accounts()]

    def _get_target_accounts(self) -> Sequence[Account]:
        return self._orgs.find_account_by_ids(self._accounts) if self._accounts else self._orgs.get_target_accounts()
