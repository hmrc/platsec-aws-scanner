from time import sleep
from typing import Any, List, Optional, Type

from botocore.client import BaseClient

from src.aws_scanner_config import AwsScannerConfig as Config
from src.data import aws_scanner_exceptions as exceptions
from src.clients.aws_athena_async_client import AwsAthenaAsyncClient


class AwsAthenaClient:
    def __init__(self, boto_athena: BaseClient):
        self._config = Config()
        self._athena_async = AwsAthenaAsyncClient(boto_athena)

    def create_database(self, database_name: str) -> None:
        self._wait_for_success(
            query_id=self._athena_async.create_database(database_name=database_name),
            timeout_seconds=self._config.athena_query_timeout_seconds(),
            raise_on_failure=exceptions.CreateDatabaseException,
        )

    def drop_database(self, database_name: str) -> None:
        self._wait_for_success(
            query_id=self._athena_async.drop_database(database_name=database_name),
            timeout_seconds=self._config.athena_query_timeout_seconds(),
            raise_on_failure=exceptions.DropDatabaseException,
        )

    def drop_table(self, database: str, table: str) -> None:
        self._wait_for_success(
            query_id=self._athena_async.drop_table(database=database, table=table),
            timeout_seconds=self._config.athena_query_timeout_seconds(),
            raise_on_failure=exceptions.DropTableException,
        )

    def list_databases(self) -> List[str]:
        return self._athena_async.list_databases()

    def list_tables(self, database: str) -> List[str]:
        return self._athena_async.list_tables(database)

    def run_query(self, database: str, query: str, raise_on_failure: Optional[Type[Exception]] = None) -> List[Any]:
        return self._wait_for_success(
            query_id=self._athena_async.run_query(query=query, database=database),
            timeout_seconds=self._config.athena_query_timeout_seconds(),
            raise_on_failure=raise_on_failure or exceptions.RunQueryException,
        )

    def _wait_for_completion(self, query_id: str, timeout_seconds: int) -> None:
        for _ in range(timeout_seconds):
            if self._athena_async.has_query_completed(query_id):
                return
            sleep(self._config.athena_query_results_polling_delay_seconds())
        raise exceptions.TimeoutException(f"query execution id: {query_id}")

    def _wait_for_success(self, query_id: str, timeout_seconds: int, raise_on_failure: Type[Exception]) -> List[Any]:
        self._wait_for_completion(query_id, timeout_seconds)
        if self._athena_async.has_query_succeeded(query_id):
            return self._athena_async.get_query_results(query_id)
        raise raise_on_failure(self._athena_async.get_query_error(query_id))
