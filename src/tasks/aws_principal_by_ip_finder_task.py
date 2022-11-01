from string import Template
from typing import Any, Dict

from src.tasks import aws_cloudtrail_scanner_queries as queries

from src.clients.aws_athena_client import AwsAthenaClient
from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.tasks.aws_cloudtrail_task import AwsCloudTrailTask
from src.data.aws_organizations_types import Account


class AwsPrincipalByIPFinderTask(AwsCloudTrailTask):
    def __init__(
        self,
        account: Account,
        partition: AwsAthenaDataPartition,
        source_ip: str,
        region: str,
    ):
        super().__init__(
            description=f"principals for source IP {source_ip}",
            account=account,
            partition=partition,
            region=region,
        )
        self._source_ip = source_ip

    def _run_task(self, client: AwsAthenaClient) -> Dict[Any, Any]:
        results = self._run_query(
            client,
            Template(queries.FIND_PRINCIPAL_BY_IP).substitute(
                database=self._database,
                account=self._account.identifier,
                source_ip=self._source_ip,
            ),
        )
        principals = sorted(list({self._read_value(results, row, 0).split(":")[-1] for row in range(len(results))}))
        return {"principals": principals}
