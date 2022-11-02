from unittest.mock import Mock, patch

import os

from src.aws_scanner_output import AwsScannerOutput

from tests.test_types_generator import account, partition, task_report
from typing import Any


EXPECTED_JSON_REPORT = (
    '[{"account": {"identifier": "account_id", "name": "account_name"}, '
    '"region": "test-region", "description": "task", "partition": '
    '{"year": "2020", "month": "11", "region": "eu"}, "results": {"key": "val"}}]'
)


@patch.dict(os.environ, {"AWS_SCANNER_REPORTS_OUTPUT": "stdout"})
def test_stdout_json_output(capsys: Any) -> None:
    AwsScannerOutput(Mock()).write("some_task", [task_report(partition=partition())])
    captured = capsys.readouterr()
    assert EXPECTED_JSON_REPORT in captured.out


@patch.dict(
    os.environ,
    {
        "AWS_SCANNER_REPORTS_ACCOUNT": "reports_account",
        "AWS_SCANNER_REPORTS_BUCKET": "reports_bucket",
        "AWS_SCANNER_REPORTS_OUTPUT": "S3",
        "AWS_SCANNER_REPORTS_ROLE": "reports_role",
    },
)
def test_s3_output() -> None:
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
        bucket="reports_bucket",
        object_name="some_task.json",
        object_content=EXPECTED_JSON_REPORT,
    )
