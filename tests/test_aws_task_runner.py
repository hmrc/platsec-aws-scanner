from unittest import TestCase
from unittest.mock import Mock, patch

from src.aws_task_runner import AwsTaskRunner
from src.data.aws_scanner_exceptions import UnsupportedTaskException
from src.tasks.aws_athena_task import AwsAthenaTask
from src.tasks.aws_audit_cost_explorer_task import AwsAuditCostExplorerTask
from src.tasks.aws_organizations_task import AwsOrganizationsTask

from tests.test_types_generator import account, athena_task, audit_iam_task, s3_task, ssm_task, task_report, vpc_task


class TestAwsTaskRunner(TestCase):
    def test_run(self) -> None:
        tasks = [athena_task(description="task_34"), athena_task(description="task_23")]
        report = [task_report(description="task_34"), task_report(description="task_23")]

        task_runner = AwsTaskRunner(Mock())
        mock_run_tasks = Mock(return_value=report)
        with patch.object(task_runner, "_run_tasks", mock_run_tasks):
            self.assertEqual(report, task_runner.run(tasks))

        mock_run_tasks.assert_called_once_with(tasks)

    def test_run_tasks(self) -> None:
        with self.assertRaises(NotImplementedError):
            AwsTaskRunner(Mock())._run_tasks([])

    def test_run_athena_task(self) -> None:
        mock_client = Mock()
        mock_client_factory = Mock(get_athena_client=Mock(return_value=mock_client))
        mock_task = Mock(
            spec=AwsAthenaTask, run=Mock(side_effect=lambda client: task_report() if client == mock_client else None)
        )
        self.assertEqual(task_report(), AwsTaskRunner(mock_client_factory)._run_task(mock_task))

    def test_run_cost_explorer_task(self) -> None:
        mock_client = Mock()
        mock_client_factory = Mock(get_cost_explorer_client=Mock(return_value=mock_client))
        mock_task = Mock(
            spec=AwsAuditCostExplorerTask,
            run=Mock(side_effect=lambda client: task_report() if client == mock_client else None),
        )
        self.assertEqual(task_report(), AwsTaskRunner(mock_client_factory)._run_task(mock_task))

    def test_run_organization_task(self) -> None:
        mock_client = Mock()
        mock_client_factory = Mock(get_organizations_client=Mock(return_value=mock_client))
        mock_task = Mock(
            spec=AwsOrganizationsTask,
            run=Mock(side_effect=lambda client: task_report() if client == mock_client else None),
        )
        self.assertEqual(task_report(), AwsTaskRunner(mock_client_factory)._run_task(mock_task))

    def test_run_ssm_task(self) -> None:
        client = Mock()
        client_factory = Mock(get_ssm_client=Mock(side_effect=lambda acc: client if acc == account() else None))
        task = ssm_task()
        task.run = Mock(side_effect=lambda c: task_report() if c == client else None)  # type: ignore
        self.assertEqual(task_report(), AwsTaskRunner(client_factory)._run_task(task))

    def test_run_s3_task(self) -> None:
        client = Mock()
        client_factory = Mock(get_s3_client=Mock(side_effect=lambda acc: client if acc == account() else None))
        task = s3_task()
        task.run = Mock(side_effect=lambda c: task_report() if c == client else None)  # type: ignore
        self.assertEqual(task_report(), AwsTaskRunner(client_factory)._run_task(task))

    def test_run_vpc_task(self) -> None:
        client = Mock()
        client_factory = Mock(get_vpc_client=Mock(side_effect=lambda acc: client if acc == account() else None))
        task = vpc_task()
        task.run = Mock(side_effect=lambda c: task_report() if c == client else None)  # type: ignore
        self.assertEqual(task_report(), AwsTaskRunner(client_factory)._run_task(task))

    def test_run_audit_iam_task(self) -> None:
        client = Mock()
        client_factory = Mock(get_iam_client=Mock(side_effect=lambda acc: client if acc == account() else None))
        task = audit_iam_task()
        task.run = Mock(side_effect=lambda c: task_report() if c == client else None)  # type: ignore
        self.assertEqual(task_report(), AwsTaskRunner(client_factory)._run_task(task))

    def test_run_unsupported_task(self) -> None:
        mock_unsupported_task = Mock()
        with self.assertRaises(UnsupportedTaskException):
            AwsTaskRunner(Mock())._run_task(mock_unsupported_task)
