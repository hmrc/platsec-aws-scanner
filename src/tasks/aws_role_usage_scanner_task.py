from string import Template
from typing import Any, Dict

from src.tasks import aws_cloudtrail_scanner_queries as queries

from src.clients.aws_athena_client import AwsAthenaClient
from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.tasks.aws_cloudtrail_task import AwsCloudTrailTask
from src.data.aws_organizations_types import Account


class AwsRoleUsageScannerTask(AwsCloudTrailTask):
    def __init__(self, account: Account, partition: AwsAthenaDataPartition, role: str):
        super().__init__(f"AWS {role} usage scan", account, partition)
        self._role = role

    def _run_task(self, client: AwsAthenaClient) -> Dict[Any, Any]:
        results = self._run_query(
            client,
            Template(queries.SCAN_ROLE_USAGE).substitute(
                database=self._database, account=self._account.identifier, role=self._role
            ),
        )
        return {
            "role_usage": [
                {
                    "event_source": self._read_value(results, row, 0),
                    "event_name": self._read_value(results, row, 1),
                    "count": int(self._read_value(results, row, 2)),
                }
                for row in range(len(results))
            ]
        }
