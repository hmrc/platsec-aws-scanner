from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from typing import Sequence

from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.data.aws_task_report import AwsTaskReport
from src.tasks.aws_cloudtrail_task import AwsCloudTrailTask
from src.aws_scanner import AwsScanner
from src.tasks.aws_athena_cleaner_task import AwsAthenaCleanerTask
from src.tasks.aws_create_athena_table_task import AwsCreateAthenaTableTask
from src.tasks.aws_principal_by_ip_finder_task import AwsPrincipalByIPFinderTask
from src.tasks.aws_role_usage_scanner_task import AwsRoleUsageScannerTask
from src.tasks.aws_service_usage_scanner_task import AwsServiceUsageScannerTask

from tests.test_types_generator import partition


class TestAwsScanner(AwsScannerTestCase):
    mock_tasks = [Mock(), Mock()]
    mock_reports = [Mock(), Mock()]

    partition, service, source_ip, role = partition(2020, 11, "us"), "ssm", "127.0.0.1", "RoleSomething"

    def principal_by_ip_finder_tasks(
        self, partition: AwsAthenaDataPartition, ip: str
    ) -> Sequence[AwsPrincipalByIPFinderTask]:
        return self.mock_tasks if partition == self.partition and ip == self.source_ip else []

    def service_usage_scanner_tasks(
        self, partition: AwsAthenaDataPartition, service: str
    ) -> Sequence[AwsServiceUsageScannerTask]:
        return self.mock_tasks if partition == self.partition and service == self.service else []

    def role_usage_scanner_tasks(
        self, partition: AwsAthenaDataPartition, role: str
    ) -> Sequence[AwsRoleUsageScannerTask]:
        return self.mock_tasks if partition == self.partition and role == self.role else []

    def create_athena_table_tasks(self, partition: AwsAthenaDataPartition) -> Sequence[AwsCreateAthenaTableTask]:
        return self.mock_tasks if partition == self.partition else []

    def clean_athena_tasks(self) -> Sequence[AwsAthenaCleanerTask]:
        return self.mock_tasks

    def mock_run(self, tasks: Sequence[AwsCloudTrailTask]) -> Sequence[AwsTaskReport]:
        return self.mock_reports if tasks == self.mock_tasks else []

    def list_accounts_tasks(self) -> Sequence[AwsTaskReport]:
        return self.mock_tasks

    def list_ssm_parameters_tasks(self) -> Sequence[AwsTaskReport]:
        return self.mock_tasks

    def audit_s3_tasks(self) -> Sequence[AwsTaskReport]:
        return self.mock_tasks

    def get_aws_scanner(self) -> AwsScanner:
        return AwsScanner(
            task_builder=Mock(
                principal_by_ip_finder_tasks=Mock(side_effect=self.principal_by_ip_finder_tasks),
                service_usage_scanner_tasks=Mock(side_effect=self.service_usage_scanner_tasks),
                role_usage_scanner_tasks=Mock(side_effect=self.role_usage_scanner_tasks),
                create_athena_table_tasks=Mock(side_effect=self.create_athena_table_tasks),
                list_accounts_tasks=Mock(side_effect=self.list_accounts_tasks),
                list_ssm_parameters_tasks=Mock(side_effect=self.list_ssm_parameters_tasks),
                clean_athena_tasks=Mock(side_effect=self.clean_athena_tasks),
                audit_s3_tasks=Mock(side_effect=self.audit_s3_tasks),
            ),
            task_runner=Mock(run=Mock(side_effect=self.mock_run)),
        )

    def test_scan_service_usage(self) -> None:
        reports = self.get_aws_scanner().scan_service_usage(self.partition, service="ssm")
        self.assertEqual(self.mock_reports, reports)

    def test_scan_role_usage(self) -> None:
        reports = self.get_aws_scanner().scan_role_usage(self.partition, role="RoleSomething")
        self.assertEqual(self.mock_reports, reports)

    def test_find_principal_by_ip(self) -> None:
        reports = self.get_aws_scanner().find_principal_by_ip(self.partition, source_ip="127.0.0.1")
        self.assertEqual(self.mock_reports, reports)

    def test_create_table(self) -> None:
        reports = self.get_aws_scanner().create_table(self.partition)
        self.assertEqual(self.mock_reports, reports)

    def test_list_accounts(self) -> None:
        self.assertEqual(self.mock_reports, self.get_aws_scanner().list_accounts())

    def test_list_ssm_parameters(self) -> None:
        self.assertEqual(self.mock_reports, self.get_aws_scanner().list_ssm_parameters())

    def test_clean_task_databases(self) -> None:
        self.assertEqual(self.mock_reports, self.get_aws_scanner().clean_athena())

    def test_audit_s3(self) -> None:
        self.assertEqual(self.mock_reports, self.get_aws_scanner().audit_s3())
