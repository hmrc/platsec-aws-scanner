from typing import Sequence

from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients.aws_client_factory import AwsClientFactory
from src.data.aws_task_report import AwsTaskReport
from src.csv_serializer import to_csv
from src.json_serializer import to_json


class AwsScannerOutput:
    def __init__(self, factory: AwsClientFactory):
        self._config = Config()
        self._factory = factory

    def write(self, task: str, reports: Sequence[AwsTaskReport]) -> None:
        output = to_csv(reports) if self._config.reports_format() == "csv" else to_json(reports)
        if self._config.reports_output().lower() == "s3":
            self._write_to_s3(f"{task}.{self._config.reports_format()}", output)
        else:
            print(output)

    def _write_to_s3(self, task: str, report: str) -> None:
        self._factory.get_s3_client(self._config.reports_account(), self._config.reports_role()).put_object(
            bucket=self._config.reports_bucket(), object_name=task, object_content=report
        )
