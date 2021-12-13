from typing import Any, Dict
from unittest import TestCase
from unittest.mock import Mock, patch

from src.aws_task_runner import AwsTaskRunner
from src.clients.aws_client_factory import AwsClientFactory
from src.data.aws_scanner_exceptions import UnsupportedClientException
from src.tasks.aws_task import AwsTask

from tests.test_types_generator import (
    account,
    athena_task,
    audit_iam_task,
    cost_explorer_task,
    organizations_task,
    s3_task,
    ssm_task,
    task_report,
    vpc_task,
)


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
        task = athena_task()
        task.run = Mock(side_effect=lambda client: task_report() if client == mock_client else None)  # type: ignore
        self.assertEqual(task_report(), AwsTaskRunner(mock_client_factory)._run_task(task))

    def test_run_cost_explorer_task(self) -> None:
        mock_client = Mock()
        mock_client_factory = Mock(get_cost_explorer_client=Mock(return_value=mock_client))
        task = cost_explorer_task()
        task.run = Mock(side_effect=lambda client: task_report() if client == mock_client else None)  # type: ignore
        self.assertEqual(task_report(), AwsTaskRunner(mock_client_factory)._run_task(task))

    def test_run_organization_task(self) -> None:
        mock_client = Mock()
        mock_client_factory = Mock(get_organizations_client=Mock(return_value=mock_client))
        task = organizations_task()
        task.run = Mock(side_effect=lambda client: task_report() if client == mock_client else None)  # type: ignore
        self.assertEqual(task_report(), AwsTaskRunner(mock_client_factory)._run_task(task))

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

    @patch("src.clients.aws_client_factory.AwsClientFactory._get_client")
    @patch("src.clients.aws_client_factory.AwsClientFactory._get_session_token")
    @patch("src.tasks.aws_task.AwsTask.run")
    def test_run_audit_iam_task(self, task_run: Any, _get_session_token: Any, _get_client: Any) -> None:
        boto_client = Mock()
        _get_client.return_value = boto_client
        task = audit_iam_task()

        AwsTaskRunner(AwsClientFactory("1234456", "username"))._run_task(task)

        _get_client.assert_called_once_with("iam", task.account, "iam_audit_role")
        task_run.assert_called_once()
        self.assertIs(boto_client, task_run.call_args.args[0]._iam)

    def test_run_unsupported_client(self) -> None:
        class UnsupportedClientTask(AwsTask):
            def _run_task(self, client: Any) -> Dict[Any, Any]:
                return dict()

        with self.assertRaisesRegex(UnsupportedClientException, "Any"):
            AwsTaskRunner(Mock())._run_task(UnsupportedClientTask("unsupported", account()))

    def test_run_unspecified_client(self) -> None:
        class UnspecifiedClientTask(AwsTask):
            def _run_task(self, client) -> Dict[Any, Any]:  # type: ignore
                return dict()

        with self.assertRaisesRegex(UnsupportedClientException, "empty"):
            AwsTaskRunner(Mock())._run_task(UnspecifiedClientTask("unspecified", account()))

    def test_run_task_with_no_client(self) -> None:
        class ClientlessTask(AwsTask):
            def _run_task(self, banana: Any) -> Dict[Any, Any]:
                return dict()

        with self.assertRaisesRegex(UnsupportedClientException, "requires a client argument"):
            AwsTaskRunner(Mock())._run_task(ClientlessTask("clientless", account()))
