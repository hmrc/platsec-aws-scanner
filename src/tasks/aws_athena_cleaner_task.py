from dataclasses import dataclass
from typing import Any, Dict, List

from src.clients.aws_athena_client import AwsAthenaClient
from src.tasks.aws_athena_task import AwsAthenaTask
from src.aws_scanner_config import AwsScannerConfig as Config


@dataclass
class AwsAthenaCleanerTask(AwsAthenaTask):
    def __init__(self) -> None:
        super().__init__("clean scanner leftovers", Config().account_cloudtrail())

    def _run_task(self, client: AwsAthenaClient) -> Dict[Any, Any]:
        databases = self._list_scanner_databases(client)
        dropped_tables = [table for tables in [self._drop_tables(client, db) for db in databases] for table in tables]
        dropped_databases = [self._drop_database(client, db) for db in databases]
        return {"dropped_tables": dropped_tables, "dropped_databases": dropped_databases}

    @staticmethod
    def _drop_tables(client: AwsAthenaClient, database: str) -> List[str]:
        return [AwsAthenaCleanerTask._drop_table(client, database, table) for table in client.list_tables(database)]

    @staticmethod
    def _drop_database(client: AwsAthenaClient, database: str) -> str:
        client.drop_database(database)
        return database

    @staticmethod
    def _list_scanner_databases(client: AwsAthenaClient) -> List[str]:
        return list(filter(lambda db: db.startswith(Config().athena_database_prefix()), client.list_databases()))

    @staticmethod
    def _drop_table(client: AwsAthenaClient, database: str, table: str) -> str:
        client.drop_table(database, table)
        return f"{database}.{table}"
