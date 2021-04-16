from time import sleep
from typing import Any, List, Type

from botocore.client import BaseClient

from src.data import aws_scanner_exceptions as exceptions
from src.clients.aws_athena_async_client import AwsAthenaAsyncClient
from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.data.aws_organizations_types import Account


class AwsAthenaClient:
    def __init__(self, boto_athena: BaseClient):
        self._athena_async = AwsAthenaAsyncClient(boto_athena)

    def create_database(self, database_name: str) -> None:
        self._wait_for_success(
            query_id=self._athena_async.create_database(database_name=database_name),
            timeout_seconds=60,
            raise_on_failure=exceptions.CreateDatabaseException,
        )

    def drop_database(self, database_name: str) -> None:
        self._wait_for_success(
            query_id=self._athena_async.drop_database(database_name=database_name),
            timeout_seconds=60,
            raise_on_failure=exceptions.DropDatabaseException,
        )

    def create_table(self, database: str, account: Account) -> None:
        self._wait_for_success(
            query_id=self._athena_async.create_table(database=database, account=account),
            timeout_seconds=60,
            raise_on_failure=exceptions.CreateTableException,
        )

    def drop_table(self, database: str, table: str) -> None:
        self._wait_for_success(
            query_id=self._athena_async.drop_table(database=database, table=table),
            timeout_seconds=60,
            raise_on_failure=exceptions.DropTableException,
        )

    def add_partition(self, database: str, account: Account, partition: AwsAthenaDataPartition) -> None:
        self._wait_for_success(
            query_id=self._athena_async.add_partition(database=database, account=account, partition=partition),
            timeout_seconds=120,
            raise_on_failure=exceptions.AddPartitionException,
        )

    def list_databases(self) -> List[str]:
        return self._athena_async.list_databases()

    def list_tables(self, database: str) -> List[str]:
        return self._athena_async.list_tables(database)

    def run_query(self, database: str, query: str) -> List[Any]:
        return self._wait_for_success(
            query_id=self._athena_async.run_query(query=query, database=database),
            timeout_seconds=300,
            raise_on_failure=exceptions.RunQueryException,
        )

    def _wait_for_completion(self, query_id: str, timeout_seconds: int) -> None:
        for _ in range(timeout_seconds):
            if self._athena_async.has_query_completed(query_id):
                return
            sleep(self._get_default_delay())
        raise exceptions.TimeoutException(f"query execution id: {query_id}")

    def _wait_for_success(self, query_id: str, timeout_seconds: int, raise_on_failure: Type[Exception]) -> List[Any]:
        self._wait_for_completion(query_id, timeout_seconds)
        if self._athena_async.has_query_succeeded(query_id):
            return self._athena_async.get_query_results(query_id)
        raise raise_on_failure(self._athena_async.get_query_error(query_id))

    @staticmethod
    def _get_default_delay() -> int:
        return 1
