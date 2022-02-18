from logging import getLogger
from string import Template
from time import sleep
from typing import Any, Dict, List, Type

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from src.data import aws_scanner_exceptions as exceptions
from src.clients import aws_athena_system_queries as queries
from src.clients.aws_athena_query_states import COMPLETED_STATES, SUCCESS_STATES
from src.aws_scanner_config import AwsScannerConfig as Config


class AwsAthenaAsyncClient:
    def __init__(self, boto_athena: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._boto_athena = boto_athena
        self._catalog = "AwsDataCatalog"
        self._config = Config()

    def create_database(self, database_name: str) -> str:
        self._logger.info(f"creating database {database_name}")
        return self.run_query(
            query=Template(queries.CREATE_DATABASE).substitute(database_name=database_name),
            raise_on_failure=exceptions.CreateDatabaseException,
        )

    def drop_database(self, database_name: str) -> str:
        self._logger.info(f"dropping database {database_name}")
        return self.run_query(
            query=Template(queries.DROP_DATABASE).substitute(database_name=database_name),
            raise_on_failure=exceptions.DropDatabaseException,
        )

    def create_table(self, database: str, table: str, query_template: str, query_attributes: Dict[str, str]) -> str:
        self._logger.info(f"creating table {table} in database {database}")
        return self.run_query(
            query=Template(query_template).substitute(**query_attributes),
            database=database,
            raise_on_failure=exceptions.CreateTableException,
        )

    def drop_table(self, database: str, table: str) -> str:
        self._logger.info(f"dropping table {table} in database {database}")
        return self.run_query(
            query=Template(queries.DROP_TABLE).substitute(table=table),
            database=database,
            raise_on_failure=exceptions.DropTableException,
        )

    def add_partition(self, database: str, table: str, query_template: str, query_attributes: Dict[str, str]) -> str:
        self._logger.info(f"loading partition {query_attributes} for table {table} in database {database}")
        return self.run_query(
            query=Template(query_template).substitute(**query_attributes),
            database=database,
            raise_on_failure=exceptions.AddPartitionException,
        )

    def has_query_completed(self, query_id: str) -> bool:
        return self._is_query_state_in(query_id, COMPLETED_STATES)

    def has_query_succeeded(self, query_id: str) -> bool:
        return self._is_query_state_in(query_id, SUCCESS_STATES)

    def get_query_results(self, query_id: str) -> List[Any]:
        self._logger.debug(f"fetching results for query {query_id}")
        try:
            query_result_response = self._boto_athena.get_query_results(QueryExecutionId=query_id)
            return list(query_result_response["ResultSet"]["Rows"][1:])
        except (BotoCoreError, ClientError) as error:
            raise exceptions.GetQueryResultsException(f"query {query_id} results unknown: {error}") from None

    def get_query_error(self, query_id: str) -> str:
        return str(self._get_query_execution(query_id)["QueryExecution"]["Status"]["StateChangeReason"])

    def run_query(
        self,
        query: str,
        database: str = "",
        raise_on_failure: Type[Exception] = exceptions.RunQueryException,
    ) -> str:
        sleep(self._config.athena_query_throttling_seconds())
        self._logger.debug(f"running query {query}")
        try:
            query_execution_response = self._boto_athena.start_query_execution(
                QueryString=query,
                QueryExecutionContext=self._build_exec_context(database),
                ResultConfiguration={"OutputLocation": f"s3://{self._config.athena_query_results_bucket()}"},
            )
            return str(query_execution_response["QueryExecutionId"])
        except (BotoCoreError, ClientError) as error:
            raise raise_on_failure(f"query execution failure: {error}") from None

    def list_tables(self, database: str) -> List[str]:
        self._logger.info(f"listing tables in database {database}")
        try:
            response = self._boto_athena.list_table_metadata(CatalogName=self._catalog, DatabaseName=database)
            return [table["Name"] for table in response["TableMetadataList"]]
        except (BotoCoreError, ClientError) as error:
            raise exceptions.ListTablesException(error) from None

    def list_databases(self) -> List[str]:
        self._logger.info("listing databases")
        try:
            response = self._boto_athena.list_databases(CatalogName=self._catalog)
            return [db["Name"] for db in response["DatabaseList"]]
        except (BotoCoreError, ClientError) as error:
            raise exceptions.ListTablesException(error) from None

    def _is_query_state_in(self, query_id: str, expected_states: List[str]) -> bool:
        return self._get_query_execution(query_id)["QueryExecution"]["Status"]["State"] in expected_states

    def _build_exec_context(self, database: str) -> Dict[str, str]:
        return {"Catalog": self._catalog, "Database": database} if database else {"Catalog": self._catalog}

    def _get_query_execution(self, query_id: str) -> Dict[Any, Any]:
        self._logger.debug(f"polling execution state for query {query_id}")
        try:
            return dict(self._boto_athena.get_query_execution(QueryExecutionId=query_id))
        except (BotoCoreError, ClientError) as error:
            raise exceptions.UnknownQueryStateException(f"query {query_id} state unknown: {error}") from None
