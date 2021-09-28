from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from typing import Any, Dict, Sequence

from src.aws_scanner_argument_parser import AwsScannerCommands as Cmd
from src.aws_task_builder import AwsTaskBuilder
from src.tasks.aws_athena_cleaner_task import AwsAthenaCleanerTask
from src.tasks.aws_audit_s3_task import AwsAuditS3Task
from src.tasks.aws_cost_explorer_task import AwsCostExplorerTask
from src.tasks.aws_audit_vpc_flow_logs_task import AwsAuditVPCFlowLogsTask
from src.tasks.aws_create_athena_table_task import AwsCreateAthenaTableTask
from src.tasks.aws_list_accounts_task import AwsListAccountsTask
from src.tasks.aws_list_ssm_parameters_task import AwsListSSMParametersTask
from src.tasks.aws_principal_by_ip_finder_task import AwsPrincipalByIPFinderTask
from src.tasks.aws_role_usage_scanner_task import AwsRoleUsageScannerTask
from src.tasks.aws_service_usage_scanner_task import AwsServiceUsageScannerTask
from src.tasks.aws_task import AwsTask

from tests.test_types_generator import account, partition
from tests.test_types_generator import aws_scanner_arguments as args

acct1 = account("999888777666")
acct2 = account("555444333222")
acct3 = account("3")
acct4 = account("4")


class TestAwsTaskBuilder(AwsScannerTestCase):
    def test_principal_by_ip_finder_tasks(self) -> None:
        self.assert_tasks_equal(
            [
                AwsPrincipalByIPFinderTask(acct1, partition(), "127.0.0.1"),
                AwsPrincipalByIPFinderTask(acct2, partition(), "127.0.0.1"),
            ],
            task_builder().build_tasks(args(task=Cmd.find_principal, source_ip="127.0.0.1")),
        )

    def test_service_usage_scanner_tasks(self) -> None:
        self.assert_tasks_equal(
            [
                AwsServiceUsageScannerTask(acct1, partition(), "s3"),
                AwsServiceUsageScannerTask(acct2, partition(), "s3"),
            ],
            task_builder().build_tasks(args(task=Cmd.service_usage, service="s3")),
        )

    # def test_cost_explorer_scanner_tasks(self) -> None:
    #     self.assert_tasks_equal(
    #         [
    #             AwsCostExplorerTask(2021, 8),
    #             AwsCostExplorerTask(2021, 7)
    #         ],
    #         task_builder().build_tasks(args(task=Cmd.cost_explorer, service="lambda", year="2021", month="08")),
    #     )

    def test_role_usage_scanner_tasks(self) -> None:
        self.assert_tasks_equal(
            [
                AwsRoleUsageScannerTask(acct1, partition(year=2020, month=10), "SomeRole"),
                AwsRoleUsageScannerTask(acct2, partition(year=2020, month=10), "SomeRole"),
            ],
            task_builder().build_tasks(args(task=Cmd.role_usage, role="SomeRole", year=2020, month=10)),
        )

    def test_create_athena_table_tasks(self) -> None:
        self.assert_tasks_equal(
            [AwsCreateAthenaTableTask(acct3, partition()), AwsCreateAthenaTableTask(acct4, partition())],
            task_builder().build_tasks(args(task=Cmd.create_table, accounts=[])),
        )

    def test_clean_athena_tasks(self) -> None:
        self.assert_tasks_equal([AwsAthenaCleanerTask()], task_builder().build_tasks(args(task=Cmd.drop)))

    def test_list_accounts_tasks(self) -> None:
        self.assert_tasks_equal([AwsListAccountsTask()], task_builder().build_tasks(args(task=Cmd.list_accounts)))

    def test_list_ssm_parameters_tasks(self) -> None:
        self.assert_tasks_equal(
            [AwsListSSMParametersTask(acct1), AwsListSSMParametersTask(acct2)],
            task_builder().build_tasks(args(task=Cmd.list_ssm_parameters)),
        )

    def test_audit_s3_tasks(self) -> None:
        self.assert_tasks_equal(
            [AwsAuditS3Task(acct1), AwsAuditS3Task(acct2)], task_builder().build_tasks(args(task=Cmd.audit_s3))
        )

    def test_audit_vpc_flow_logs_tasks(self) -> None:
        self.assert_tasks_equal(
            [AwsAuditVPCFlowLogsTask(acct1, False), AwsAuditVPCFlowLogsTask(acct2, False)],
            task_builder().build_tasks(args(task=Cmd.audit_vpc_flow_logs, enforce=False)),
        )

    def assert_tasks_equal(self, expected: Sequence[AwsTask], actual: Sequence[AwsTask]) -> None:
        self.assertEqual(len(expected), len(actual), f"expected {len(expected)} tasks but got {len(actual)}")
        for i, task in enumerate(expected):
            self.assertEqual(to_dict(task), to_dict(actual[i]))


def task_builder() -> AwsTaskBuilder:
    mock_orgs = Mock(
        get_target_accounts=Mock(return_value=[acct3, acct4]),
        find_account_by_ids=Mock(
            side_effect=lambda ids: [acct1, acct2] if ids == [acct1.identifier, acct2.identifier] else []
        ),
    )
    return AwsTaskBuilder(mock_orgs)


def to_dict(task: AwsTask) -> Dict[str, Any]:
    return {**vars(task), "__type": type(task), "_database": None, "_logger": None}
