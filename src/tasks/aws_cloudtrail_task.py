from random import randint
from typing import Any, Dict, List

from src.clients.aws_athena_client import AwsAthenaClient
from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.tasks.aws_athena_task import AwsAthenaTask
from src.data.aws_organizations_types import Account
from src.aws_scanner_config import AwsScannerConfig as Config
from src.data.aws_task_report import AwsTaskReport


class AwsCloudTrailTask(AwsAthenaTask):
    def __init__(self, description: str, account: Account, partition: AwsAthenaDataPartition):
        super().__init__(description, account)
        self._database = self._randomise_name(account.identifier)
        self._partition = partition

    def run(self, client: AwsAthenaClient) -> AwsTaskReport:
        self._setup(client)
        try:
            self._logger.info(f"running {self}")
            results = self._run_task(client)
        finally:
            self._teardown(client)
        return AwsTaskReport(self._account, self._description, self._partition, results)

    def _setup(self, client: AwsAthenaClient) -> None:
        self._logger.info(f"setting up {self}")
        client.create_database(self._database)
        client.create_table(self._database, self._account)
        client.add_partition(self._database, self._account, self._partition)

    def _run_task(self, client: AwsAthenaClient) -> Dict[Any, Any]:
        raise NotImplementedError("this is an abstract class")

    def _teardown(self, client: AwsAthenaClient) -> None:
        self._logger.info(f"tearing down {self}")
        client.drop_table(self._database, self._account.identifier)
        client.drop_database(self._database)

    def _run_query(self, client: AwsAthenaClient, query: str) -> List[Any]:
        return client.run_query(database=self._database, query=query)

    @staticmethod
    def _randomise_name(name: str) -> str:
        return f"{Config().athena_database_prefix()}_{name}_{''.join([str(randint(0, 9)) for _ in range(10)])}"

    @staticmethod
    def _read_value(results: List[Any], row_index: int, item_index: int) -> str:
        return str(results[row_index]["Data"][item_index].get("VarCharValue", ""))

    def __str__(self) -> str:
        return f"{super().__str__()} with {self._partition}"
