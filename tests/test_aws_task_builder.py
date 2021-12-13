from pytest import raises
from unittest import TestCase
from unittest.mock import Mock

from typing import Any, Dict, Sequence

from src.aws_scanner_argument_parser import AwsScannerCommands as Cmd, AwsScannerArguments
from src.aws_task_builder import AwsTaskBuilder
from src.data.aws_scanner_exceptions import UnsupportedTaskException
from src.tasks.aws_athena_cleaner_task import AwsAthenaCleanerTask
from src.tasks.aws_audit_s3_task import AwsAuditS3Task
from src.tasks.aws_audit_iam_task import AwsAuditIamTask
from src.tasks.aws_audit_vpc_flow_logs_task import AwsAuditVPCFlowLogsTask
from src.tasks.aws_create_athena_table_task import AwsCreateAthenaTableTask
from src.tasks.aws_list_accounts_task import AwsListAccountsTask
from src.tasks.aws_list_ssm_parameters_task import AwsListSSMParametersTask
from src.tasks.aws_principal_by_ip_finder_task import AwsPrincipalByIPFinderTask
from src.tasks.aws_role_usage_scanner_task import AwsRoleUsageScannerTask
from src.tasks.aws_service_usage_scanner_task import AwsServiceUsageScannerTask
from src.tasks.aws_audit_cost_explorer_task import AwsAuditCostExplorerTask
from src.tasks.aws_audit_password_policy_task import AwsAuditPasswordPolicyTask
from src.tasks.aws_task import AwsTask

from tests.test_types_generator import account, partition, audit_cloudtrail_task
from tests.test_types_generator import aws_scanner_arguments as args

acct1 = account("999888777666")
acct2 = account("555444333222")
acct3 = account("3")
acct4 = account("4")


class TestAwsTaskBuilder(TestCase):
    def test_account_id_as_name_when_account_lookup_disabled(self) -> None:
        factory = Mock()
        accounts = AwsTaskBuilder(factory, args(disable_account_lookup=True))._get_target_accounts(["1234"])
        factory.assert_not_called()
        assert [account("1234", "1234")] == accounts

    def test_exit_when_account_lookup_disabled_and_no_target_account_provided(self) -> None:
        with raises(SystemExit, match="account lookup is disabled and no target accounts were provided"):
            AwsTaskBuilder(Mock(), args(disable_account_lookup=True))._get_target_accounts([])

    def test_principal_by_ip_finder_tasks(self) -> None:
        self.assert_tasks_equal(
            [
                AwsPrincipalByIPFinderTask(acct1, partition(), "127.0.0.1"),
                AwsPrincipalByIPFinderTask(acct2, partition(), "127.0.0.1"),
            ],
            task_builder(args(task=Cmd.find_principal, source_ip="127.0.0.1")).build_tasks(),
        )

    def test_service_usage_scanner_tasks(self) -> None:
        self.assert_tasks_equal(
            [
                AwsServiceUsageScannerTask(acct1, partition(), "s3"),
                AwsServiceUsageScannerTask(acct1, partition(), "ssm"),
                AwsServiceUsageScannerTask(acct2, partition(), "s3"),
                AwsServiceUsageScannerTask(acct2, partition(), "ssm"),
            ],
            task_builder(args(task=Cmd.service_usage, services=["s3", "ssm"])).build_tasks(),
        )

    def test_cost_explorer_scanner_tasks(self) -> None:
        self.assert_tasks_equal(
            [
                AwsAuditCostExplorerTask(acct1, "a_service", 2021, 8),
                AwsAuditCostExplorerTask(acct2, "a_service", 2021, 8),
            ],
            task_builder(args(task=Cmd.cost_explorer, services=["a_service"], year=2021, month=8)).build_tasks(),
        )

    def test_role_usage_scanner_tasks(self) -> None:
        self.assert_tasks_equal(
            [
                AwsRoleUsageScannerTask(acct1, partition(year=2020, month=10), "SomeRole"),
                AwsRoleUsageScannerTask(acct2, partition(year=2020, month=10), "SomeRole"),
            ],
            task_builder(args(task=Cmd.role_usage, role="SomeRole", year=2020, month=10)).build_tasks(),
        )

    def test_create_athena_table_tasks(self) -> None:
        self.assert_tasks_equal(
            [AwsCreateAthenaTableTask(acct3, partition()), AwsCreateAthenaTableTask(acct4, partition())],
            task_builder(args(task=Cmd.create_table, accounts=[])).build_tasks(),
        )

    def test_clean_athena_tasks(self) -> None:
        self.assert_tasks_equal([AwsAthenaCleanerTask()], task_builder(args(task=Cmd.drop)).build_tasks())

    def test_list_accounts_tasks(self) -> None:
        self.assert_tasks_equal([AwsListAccountsTask()], task_builder(args(task=Cmd.list_accounts)).build_tasks())

    def test_list_ssm_parameters_tasks(self) -> None:
        self.assert_tasks_equal(
            [AwsListSSMParametersTask(acct1), AwsListSSMParametersTask(acct2)],
            task_builder(args(task=Cmd.list_ssm_parameters)).build_tasks(),
        )

    def test_audit_s3_tasks(self) -> None:
        self.assert_tasks_equal(
            [AwsAuditS3Task(acct1), AwsAuditS3Task(acct2)], task_builder(args(task=Cmd.audit_s3)).build_tasks()
        )

    def test_audit_vpc_flow_logs_tasks(self) -> None:
        self.assert_tasks_equal(
            [AwsAuditVPCFlowLogsTask(acct1, False, True), AwsAuditVPCFlowLogsTask(acct2, False, True)],
            task_builder(
                args(task=Cmd.audit_vpc_flow_logs, enforce=False, with_subscription_filter=True)
            ).build_tasks(),
        )

    def test_audit_iam_tasks(self) -> None:
        self.assert_tasks_equal(
            [AwsAuditIamTask(acct1), AwsAuditIamTask(acct2)],
            task_builder(args(task=Cmd.audit_iam)).build_tasks(),
        )

    def test_audit_password_policy_task(self) -> None:
        self.assert_tasks_equal(
            [AwsAuditPasswordPolicyTask(acct1, True), AwsAuditPasswordPolicyTask(acct2, True)],
            task_builder(args(task=Cmd.audit_password_policy, enforce=True)).build_tasks(),
        )

    def test_audit_cloudtrail_task(self) -> None:
        self.assert_tasks_equal(
            [(audit_cloudtrail_task(account=acct1)), (audit_cloudtrail_task(account=acct2))],
            task_builder(args(task=Cmd.audit_cloudtrail)).build_tasks(),
        )

    def test_unsupported_task(self) -> None:
        with self.assertRaisesRegex(UnsupportedTaskException, "banana"):
            task_builder(args(task="banana")).build_tasks()

    def assert_tasks_equal(self, expected: Sequence[AwsTask], actual: Sequence[AwsTask]) -> None:
        self.assertEqual(len(expected), len(actual), f"expected {len(expected)} tasks but got {len(actual)}")
        for i, task in enumerate(expected):
            self.assertEqual(to_dict(task), to_dict(actual[i]))


def task_builder(args: AwsScannerArguments) -> AwsTaskBuilder:
    mock_orgs = Mock(
        get_target_accounts=Mock(return_value=[acct3, acct4]),
        find_account_by_ids=Mock(
            side_effect=lambda ids: [acct1, acct2] if ids == [acct1.identifier, acct2.identifier] else []
        ),
    )
    mock_client_factory = Mock(get_organizations_client=Mock(return_value=mock_orgs))
    return AwsTaskBuilder(factory=mock_client_factory, args=args)


def to_dict(task: AwsTask) -> Dict[str, Any]:
    return {**vars(task), "__type": type(task), "_database": None, "_logger": None}
