from datetime import date
from pytest import raises
from unittest import TestCase
from unittest.mock import Mock

from typing import Any, Dict, Sequence

from src.aws_scanner_argument_parser import (
    AwsScannerCommands as Cmd,
    AwsScannerArguments,
)
from src.aws_task_builder import AwsTaskBuilder
from src.data.aws_scanner_exceptions import UnsupportedTaskException
from src.tasks.aws_athena_cleaner_task import AwsAthenaCleanerTask
from src.tasks.aws_audit_cost_explorer_task import AwsAuditCostExplorerTask
from src.tasks.aws_audit_iam_task import AwsAuditIamTask
from src.tasks.aws_audit_password_policy_task import AwsAuditPasswordPolicyTask
from src.tasks.aws_audit_s3_task import AwsAuditS3Task
from src.tasks.aws_audit_vpc_flow_logs_task import AwsAuditVPCFlowLogsTask
from src.tasks.aws_audit_vpc_dns_logs_task import AwsAuditVPCDnsLogsTask
from src.tasks.aws_create_athena_table_task import AwsCreateAthenaTableTask
from src.tasks.aws_list_accounts_task import AwsListAccountsTask
from src.tasks.aws_list_ssm_parameters_task import AwsListSSMParametersTask
from src.tasks.aws_principal_by_ip_finder_task import AwsPrincipalByIPFinderTask
from src.tasks.aws_role_usage_scanner_task import AwsRoleUsageScannerTask
from src.tasks.aws_service_usage_scanner_task import AwsServiceUsageScannerTask
from src.tasks.aws_task import AwsTask

from tests.test_types_generator import (
    account,
    audit_cloudtrail_task,
    audit_central_logging_task,
    audit_ec2_instances_task,
    audit_vpc_peering_task,
    create_flow_logs_table_task,
    partition,
    TEST_REGION,
)
from tests.test_types_generator import aws_scanner_arguments as args


acct1 = account("999888777666")
acct2 = account("555444333222")
acct3 = account("3")
acct4 = account("4")


class TestAwsTaskBuilder(TestCase):
    def test_account_id_as_name_when_account_lookup_disabled(self) -> None:
        factory = Mock()
        accounts = AwsTaskBuilder(factory, args(accounts=["1234"], disable_account_lookup=True))._get_target_accounts()
        factory.assert_not_called()
        assert [account("1234", "1234")] == accounts

    def test_exit_when_account_lookup_disabled_and_no_target_account_provided(
        self,
    ) -> None:
        with raises(
            SystemExit,
            match="account lookup is disabled and no target accounts were provided",
        ):
            AwsTaskBuilder(Mock(), args(accounts=[], disable_account_lookup=True))._get_target_accounts()

    def test_principal_by_ip_finder_tasks(self) -> None:
        self.assert_tasks_equal(
            [
                AwsPrincipalByIPFinderTask(acct1, partition(), "127.0.0.1", TEST_REGION),
                AwsPrincipalByIPFinderTask(acct2, partition(), "127.0.0.1", TEST_REGION),
            ],
            task_builder(args(task=Cmd.find_principal, source_ip="127.0.0.1", region=TEST_REGION)).build_tasks(),
        )

    def test_service_usage_scanner_tasks(self) -> None:
        self.assert_tasks_equal(
            [
                AwsServiceUsageScannerTask(acct1, partition(), "s3", TEST_REGION),
                AwsServiceUsageScannerTask(acct1, partition(), "ssm", TEST_REGION),
                AwsServiceUsageScannerTask(acct2, partition(), "s3", TEST_REGION),
                AwsServiceUsageScannerTask(acct2, partition(), "ssm", TEST_REGION),
            ],
            task_builder(args(task=Cmd.service_usage, services=["s3", "ssm"], region=TEST_REGION)).build_tasks(),
        )

    def test_cost_explorer_scanner_tasks(self) -> None:
        tasks = task_builder(args(task=Cmd.cost_explorer, region=TEST_REGION)).build_tasks()

        self.assert_tasks_equal(
            [
                AwsAuditCostExplorerTask(acct1, date(2020, 11, 2), TEST_REGION),
                AwsAuditCostExplorerTask(acct2, date(2020, 11, 2), TEST_REGION),
            ],
            tasks,
        )

    def test_role_usage_scanner_tasks(self) -> None:
        self.assert_tasks_equal(
            [
                AwsRoleUsageScannerTask(acct1, partition(year=2020, month=10), "SomeRole", TEST_REGION),
                AwsRoleUsageScannerTask(acct2, partition(year=2020, month=10), "SomeRole", TEST_REGION),
            ],
            task_builder(
                args(
                    task=Cmd.role_usage,
                    role="SomeRole",
                    year=2020,
                    month=10,
                    region=TEST_REGION,
                )
            ).build_tasks(),
        )

    def test_create_athena_table_tasks(self) -> None:
        self.assert_tasks_equal(
            [
                AwsCreateAthenaTableTask(acct3, partition(), TEST_REGION),
                AwsCreateAthenaTableTask(acct4, partition(), TEST_REGION),
            ],
            task_builder(args(task=Cmd.create_table, accounts=[], region=TEST_REGION)).build_tasks(),
        )

    def test_clean_athena_tasks(self) -> None:
        self.assert_tasks_equal(
            [AwsAthenaCleanerTask(region=TEST_REGION)],
            task_builder(args(task=Cmd.drop, region=TEST_REGION)).build_tasks(),
        )

    def test_list_accounts_tasks(self) -> None:
        self.assert_tasks_equal(
            [AwsListAccountsTask(region=TEST_REGION)],
            task_builder(args(task=Cmd.list_accounts, region=TEST_REGION)).build_tasks(),
        )

    def test_list_ssm_parameters_tasks(self) -> None:
        self.assert_tasks_equal(
            [
                AwsListSSMParametersTask(acct1, TEST_REGION),
                AwsListSSMParametersTask(acct2, TEST_REGION),
            ],
            task_builder(args(task=Cmd.list_ssm_parameters, region=TEST_REGION)).build_tasks(),
        )

    def test_audit_s3_tasks(self) -> None:
        self.assert_tasks_equal(
            [AwsAuditS3Task(acct1, TEST_REGION), AwsAuditS3Task(acct2, TEST_REGION)],
            task_builder(args(task=Cmd.audit_s3, region=TEST_REGION)).build_tasks(),
        )

    def test_audit_vpc_flow_logs_tasks(self) -> None:
        self.assert_tasks_equal(
            [
                AwsAuditVPCFlowLogsTask(acct1, False, True, False, TEST_REGION),
                AwsAuditVPCFlowLogsTask(acct2, False, True, False, TEST_REGION),
            ],
            task_builder(
                args(
                    task=Cmd.audit_vpc_flow_logs,
                    enforce=False,
                    with_subscription_filter=True,
                    skip_tags=False,
                    region=TEST_REGION,
                )
            ).build_tasks(),
        )

    def test_audit_vpc_dns_logs_tasks(self) -> None:
        self.assert_tasks_equal(
            [
                AwsAuditVPCDnsLogsTask(acct1, False, True, False, TEST_REGION),
                AwsAuditVPCDnsLogsTask(acct2, False, True, False, TEST_REGION),
            ],
            task_builder(
                args(
                    task=Cmd.audit_vpc_dns_logs,
                    enforce=False,
                    with_subscription_filter=True,
                    skip_tags=False,
                    region=TEST_REGION,
                )
            ).build_tasks(),
        )

    def test_audit_iam_tasks(self) -> None:
        self.assert_tasks_equal(
            [AwsAuditIamTask(acct1, TEST_REGION), AwsAuditIamTask(acct2, TEST_REGION)],
            task_builder(args(task=Cmd.audit_iam, region=TEST_REGION)).build_tasks(),
        )

    def test_audit_password_policy_task(self) -> None:
        self.assert_tasks_equal(
            [
                AwsAuditPasswordPolicyTask(acct1, True, TEST_REGION),
                AwsAuditPasswordPolicyTask(acct2, True, TEST_REGION),
            ],
            task_builder(args(task=Cmd.audit_password_policy, enforce=True, region=TEST_REGION)).build_tasks(),
        )

    def test_audit_cloudtrail_task(self) -> None:
        self.assert_tasks_equal(
            [
                (audit_cloudtrail_task(account=acct1)),
                (audit_cloudtrail_task(account=acct2)),
            ],
            task_builder(args(task=Cmd.audit_cloudtrail, region=TEST_REGION)).build_tasks(),
        )

    def test_audit_central_logging_task(self) -> None:
        self.assert_tasks_equal(
            [audit_central_logging_task()],
            task_builder(args(task=Cmd.audit_central_logging, region=TEST_REGION)).build_tasks(),
        )

    def test_create_flow_logs_table_task(self) -> None:
        self.assert_tasks_equal(
            [create_flow_logs_table_task(partition=partition(year=2020, month=11, day=1))],
            task_builder(
                args(
                    task=Cmd.create_flow_logs_table,
                    year=2020,
                    month=11,
                    day=1,
                    region=TEST_REGION,
                )
            ).build_tasks(),
        )

    def test_audit_vpc_peering_task(self) -> None:
        self.assert_tasks_equal(
            [audit_vpc_peering_task(acct1), audit_vpc_peering_task(acct2)],
            task_builder(args(task=Cmd.audit_vpc_peering, region=TEST_REGION)).build_tasks(),
        )

    def test_audit_ec2_instances_task(self) -> None:
        self.assert_tasks_equal(
            [audit_ec2_instances_task(acct1), audit_ec2_instances_task(acct2)],
            task_builder(args(task=Cmd.audit_ec2_instances, region=TEST_REGION)).build_tasks(),
        )

    def test_unsupported_task(self) -> None:
        with self.assertRaisesRegex(UnsupportedTaskException, "banana"):
            task_builder(args(task="banana")).build_tasks()

    def assert_tasks_equal(self, expected: Sequence[AwsTask], actual: Sequence[AwsTask]) -> None:
        self.assertEqual(
            len(expected),
            len(actual),
            f"expected {len(expected)} tasks but got {len(actual)}",
        )
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
    return {
        **vars(task),
        "__type": type(task),
        "_database": None,
        "_logger": None,
        "_config": None,
    }
