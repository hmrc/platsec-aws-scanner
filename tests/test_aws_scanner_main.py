from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, patch

from src.aws_scanner_main import AwsScannerMain
from src.data.aws_scanner_exceptions import ClientFactoryException

from tests.test_types_generator import aws_scanner_arguments, aws_task, task_report


client = Mock()
mock_factory = Mock(get_organizations_client=Mock(return_value=client))
tasks = [aws_task(description="task_1"), aws_task(description="task_2")]
mock_task_builder = Mock(build_tasks=Mock(return_value=tasks))
reports = [task_report(description="report_1"), task_report(description="report_2")]
mock_task_runner = Mock(run=Mock(return_value=reports))
mock_output = Mock()


class TestMain(AwsScannerTestCase):
    @patch("src.aws_scanner_main.AwsClientFactory", return_value=mock_factory)
    @patch("src.aws_scanner_main.AwsTaskBuilder", return_value=mock_task_builder)
    @patch("src.aws_scanner_main.AwsParallelTaskRunner", return_value=mock_task_runner)
    @patch("src.aws_scanner_main.AwsScannerOutput", return_value=mock_output)
    def test_main(self, output: Mock, task_runner: Mock, task_builder: Mock, factory: Mock) -> None:
        args = aws_scanner_arguments(task="service_usage", services=["ssm"], year=2020, month=10, region="us")
        AwsScannerMain(args)
        factory.assert_called_once_with(mfa="123456", username="bob")
        task_builder.assert_called_once_with(client)
        mock_task_builder.build_tasks.assert_called_once_with(args)
        task_runner.assert_called_once_with(mock_factory)
        mock_task_runner.run.assert_called_once_with(tasks)
        output.assert_called_once_with(mock_factory)
        mock_output.write.assert_called_once_with("service_usage", reports)

    @patch("src.aws_scanner_main.AwsClientFactory", side_effect=ClientFactoryException)
    def test_main_failure(self, _: Mock) -> None:
        with self.assertRaises(SystemExit) as se:
            with self.assertLogs("AwsScannerMain", level="ERROR") as error_log:
                AwsScannerMain(aws_scanner_arguments(task="drop"))
        self.assertEqual(1, se.exception.code, f"exit code should be 1 but got {se.exception.code}")
        self.assertIn("ClientFactoryException", error_log.output[0])
