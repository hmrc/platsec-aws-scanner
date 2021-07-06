from string import Template
from typing import Any, Dict

from src.tasks import aws_cloudtrail_scanner_queries as queries

from src.clients.aws_athena_client import AwsAthenaClient
from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.tasks.aws_cloudtrail_task import AwsCloudTrailTask
from src.data.aws_organizations_types import Account


class AwsServiceUsageScannerTask(AwsCloudTrailTask):
    def __init__(self, account: Account, partition: AwsAthenaDataPartition, service: str):
        super().__init__(f"AWS {service} service usage scan", account, partition)
        self._service = service

    def _run_task(self, client: AwsAthenaClient) -> Dict[Any, Any]:
        results = self._run_query(
            client,
            Template(queries.SCAN_SERVICE_USAGE).substitute(
                database=self._database, account=self._account.identifier, service=self._service
            ),
        )
        return {
            "event_source": self._read_value(results, 0, 0) if results else self._service,
            "service_usage": [
                {
                    "event_name": self._read_value(results, row, 1),
                    "error_code": self._read_value(results, row, 2),
                    "count": int(self._read_value(results, row, 3)),
                }
                for row in range(len(results))
            ],
        }
