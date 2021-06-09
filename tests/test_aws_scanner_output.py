from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, patch

import os

from contextlib import redirect_stdout
from io import StringIO

from src.aws_scanner_output import AwsScannerOutput

from tests.test_types_generator import account, partition, task_report


EXPECTED_JSON_REPORT = (
    '[{"account": {"identifier": "account_id", "name": "account_name"}, "description": "task", "partition": '
    '{"year": "2020", "month": "11", "region": "eu"}, "results": {"key": "val"}}]'
)


class TestAwsScannerOutput(AwsScannerTestCase):
    @patch.dict(os.environ, {"AWS_SCANNER_REPORTS_OUTPUT": "stdout"}, clear=True)
    def test_stdout_output(self) -> None:
        with redirect_stdout(StringIO()) as out:
            AwsScannerOutput(Mock()).write("some_task", [task_report(partition=partition())])
        self.assertEqual(EXPECTED_JSON_REPORT, out.getvalue().strip())

    @patch.dict(
        os.environ,
        {
            "AWS_SCANNER_REPORTS_ACCOUNT": "reports_account",
            "AWS_SCANNER_REPORTS_BUCKET": "reports_bucket",
            "AWS_SCANNER_REPORTS_OUTPUT": "S3",
            "AWS_SCANNER_REPORTS_ROLE": "reports_role",
        },
        clear=True,
    )
    def test_s3_output(self) -> None:
        mock_s3 = Mock()
        factory = Mock(
            get_s3_client=Mock(
                side_effect=lambda acc, role: mock_s3
                if acc == account("reports_account", "reports") and role == "reports_role"
                else None
            )
        )
        AwsScannerOutput(factory).write("some_task", [task_report(partition=partition())])
        mock_s3.put_object.assert_called_once_with(
            bucket="reports_bucket", object_name="some_task.json", object_content=EXPECTED_JSON_REPORT
        )
