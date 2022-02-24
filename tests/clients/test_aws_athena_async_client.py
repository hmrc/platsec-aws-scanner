from unittest import TestCase
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError, ParamValidationError
from typing import Any, Dict, Type

from src.clients import aws_athena_query_states as states
from src.data import aws_scanner_exceptions as exception
from src.clients.aws_athena_async_client import AwsAthenaAsyncClient

from tests import _raise
from tests.clients import (
    test_aws_athena_system_queries as queries,
    test_aws_athena_system_queries_results as queries_results,
)


def assert_query_run(
    test: TestCase,
    method_under_test: str,
    method_args: Dict[str, Any],
    query: str,
    raise_on_failure: Type[Exception],
) -> None:
    assert_success_query_run(test, method_under_test, method_args, query, raise_on_failure)
    assert_failure_query_run(test, method_under_test, method_args, raise_on_failure)


def assert_success_query_run(
    test: TestCase,
    method_under_test: str,
    method_args: Dict[str, str],
    query: str,
    raise_on_failure: Type[Exception],
) -> None:
    with patch(
        "src.clients.aws_athena_async_client.AwsAthenaAsyncClient.run_query", return_value="1234-5678-9012"
    ) as mock_run_query:
        query_exec_response = getattr(AwsAthenaAsyncClient(Mock()), method_under_test)(**method_args)

    test.assertEqual("1234-5678-9012", query_exec_response)
    if "database" in method_args:
        mock_run_query.assert_called_once_with(
            query=query, database=method_args["database"], raise_on_failure=raise_on_failure
        )
    else:
        mock_run_query.assert_called_once_with(query=query, raise_on_failure=raise_on_failure)


def assert_failure_query_run(
    test: TestCase, method_under_test: str, method_args: Dict[str, str], raise_on_failure: Type[Exception]
) -> None:
    mock_athena = Mock(start_query_execution=Mock(side_effect=ParamValidationError(report="boom")))
    with test.assertRaises(raise_on_failure):
        getattr(AwsAthenaAsyncClient(mock_athena), method_under_test)(**method_args)


class TestQueries(TestCase):
    def test_create_database(self) -> None:
        assert_query_run(
            test=self,
            method_under_test="create_database",
            method_args={"database_name": "some_database_name"},
            query=queries.CREATE_DATABASE,
            raise_on_failure=exception.CreateDatabaseException,
        )

    def test_drop_database(self) -> None:
        assert_query_run(
            test=self,
            method_under_test="drop_database",
            method_args={"database_name": "some_database_name"},
            query=queries.DROP_DATABASE,
            raise_on_failure=exception.DropDatabaseException,
        )

    def test_drop_table(self) -> None:
        assert_query_run(
            test=self,
            method_under_test="drop_table",
            method_args={"database": "some_database", "table": "908173625490"},
            query=queries.DROP_TABLE,
            raise_on_failure=exception.DropTableException,
        )


class TestRunQuery(TestCase):
    def test_run_query_success(self) -> None:
        query = "CREATE DATABASE something"
        mock_athena = Mock(start_query_execution=Mock(return_value={"QueryExecutionId": "1234"}))

        query_id = AwsAthenaAsyncClient(mock_athena).run_query(query)

        self.assertEqual("1234", query_id)
        mock_athena.start_query_execution.assert_called_once_with(
            QueryString=query,
            QueryExecutionContext={"Catalog": "AwsDataCatalog"},
            ResultConfiguration={"OutputLocation": "s3://query-results-bucket"},
        )

    def test_run_query_in_db_success(self) -> None:
        query = "SELECT something FROM somewhere WHERE other_thing = some_value"
        database = "some_database"
        mock_athena = Mock(start_query_execution=Mock(return_value={"QueryExecutionId": "1234"}))

        query_id = AwsAthenaAsyncClient(mock_athena).run_query(query, database)

        self.assertEqual("1234", query_id)
        mock_athena.start_query_execution.assert_called_once_with(
            QueryString=query,
            QueryExecutionContext={"Catalog": "AwsDataCatalog", "Database": database},
            ResultConfiguration={"OutputLocation": "s3://query-results-bucket"},
        )

    def test_run_query_botocore_error(self) -> None:
        report = 'Unknown parameter in QueryExecutionContext: "banana", must be one of: Database, Catalog'
        mock_athena = Mock(start_query_execution=Mock(side_effect=ParamValidationError(report=report)))

        with self.assertRaises(exception.RunQueryException) as ex:
            AwsAthenaAsyncClient(mock_athena).run_query("some query")
        self.assertIn(report, ex.exception.args[0])

    def test_run_query_client_error(self) -> None:
        error_message = "MultiFactorAuthentication failed with invalid MFA one time pass code."
        mock_athena = Mock(
            start_query_execution=Mock(
                side_effect=ClientError(
                    operation_name="AssumeRole",
                    error_response={
                        "Error": {
                            "Code": "AccessDenied",
                            "Message": error_message,
                        }
                    },
                )
            )
        )
        with self.assertRaises(exception.RunQueryException) as ex:
            AwsAthenaAsyncClient(mock_athena).run_query("some query")
        self.assertIn(error_message, ex.exception.args[0])


class TestIsQueryStateIn(TestCase):
    def test_query_state_is_in_completed_states(self) -> None:
        query_id = "48068afb-edde-4e9c-bcef-6bfa29987b1a"
        for state in [states.QUERY_SUCCEEDED, states.QUERY_FAILED, states.QUERY_CANCELLED]:
            mock_athena = Mock(get_query_execution=Mock(return_value={"QueryExecution": {"Status": {"State": state}}}))
            self.assertTrue(
                AwsAthenaAsyncClient(mock_athena)._is_query_state_in(query_id, states.COMPLETED_STATES),
                f"query should be considered completed when status is {state}",
            )
            mock_athena.get_query_execution.assert_called_once_with(QueryExecutionId=query_id)

    def test_query_state_is_not_in_completed_states(self) -> None:
        query_id = "6da1f9be-772e-4a19-a542-f9f13e037707"
        for state in [states.QUERY_QUEUED, states.QUERY_RUNNING]:
            mock_athena = Mock(get_query_execution=Mock(return_value={"QueryExecution": {"Status": {"State": state}}}))
            self.assertFalse(
                AwsAthenaAsyncClient(mock_athena)._is_query_state_in(query_id, states.COMPLETED_STATES),
                f"query should not be considered completed when status is {state}",
            )
            mock_athena.get_query_execution.assert_called_once_with(QueryExecutionId=query_id)

    def test_query_state_is_unknown(self) -> None:
        query_id = "6da1f9be-772e-4a19-a542-f9f13e037707"
        error_message = "some client error"
        mock_athena = Mock(
            get_query_execution=Mock(
                side_effect=ClientError(
                    operation_name="AssumeRole",
                    error_response={
                        "Error": {
                            "Code": "AccessDenied",
                            "Message": error_message,
                        }
                    },
                )
            )
        )
        with self.assertRaises(exception.UnknownQueryStateException) as ex:
            AwsAthenaAsyncClient(mock_athena)._is_query_state_in(query_id, states.COMPLETED_STATES)
        self.assertIn(error_message, ex.exception.args[0])

    def test_has_query_completed(self) -> None:
        query_id = "4321-8765"
        with patch(
            "src.clients.aws_athena_async_client.AwsAthenaAsyncClient._is_query_state_in"
        ) as mock_is_query_state_in:
            AwsAthenaAsyncClient(Mock()).has_query_completed(query_id)
        mock_is_query_state_in.assert_called_once_with(query_id, states.COMPLETED_STATES)

    def test_has_query_succeeded(self) -> None:
        query_id = "9876-6543"
        with patch(
            "src.clients.aws_athena_async_client.AwsAthenaAsyncClient._is_query_state_in"
        ) as mock_is_query_state_in:
            AwsAthenaAsyncClient(Mock()).has_query_succeeded(query_id)
        mock_is_query_state_in.assert_called_once_with(query_id, states.SUCCESS_STATES)


class TestGetQueryResults(TestCase):
    def test_get_query_results_has_results(self) -> None:
        query_id = "48068afb-edde-4e9c-bcef-6bfa29987b1a"
        mock_athena = Mock(get_query_results=Mock(return_value=queries_results.GET_EVENT_USAGE_COUNT_RESULTS))
        self.assertEqual(
            [
                {"Data": [{"VarCharValue": "GetParameter"}, {"VarCharValue": "274"}]},
                {"Data": [{"VarCharValue": "DescribeInstanceInformation"}, {"VarCharValue": "1"}]},
                {"Data": [{"VarCharValue": "GetParameters"}, {"VarCharValue": "570"}]},
                {"Data": [{"VarCharValue": "ListAssociations"}, {"VarCharValue": "1"}]},
            ],
            AwsAthenaAsyncClient(mock_athena).get_query_results(query_id),
        )
        mock_athena.get_query_results.assert_called_once_with(QueryExecutionId=query_id)

    def test_get_query_results_has_empty_results(self) -> None:
        query_id = "48068afb-edde-4e9c-bcef-6bfa29987b1a"
        mock_athena = Mock(get_query_results=Mock(return_value=queries_results.GET_EVENT_USAGE_COUNT_EMPTY_RESULTS))
        self.assertEqual([], AwsAthenaAsyncClient(mock_athena).get_query_results(query_id))
        mock_athena.get_query_results.assert_called_once_with(QueryExecutionId=query_id)

    def test_get_query_results_failure(self) -> None:
        query_id = "6da1f9be-772e-4a19-a542-f9f13e037707"
        error_message = "Query has not yet finished. Current state: QUEUED"
        mock_athena = Mock(
            get_query_results=Mock(
                side_effect=ClientError(
                    operation_name="GetQueryResults",
                    error_response={
                        "Error": {
                            "Code": "InvalidRequestException",
                            "Message": error_message,
                        }
                    },
                )
            )
        )
        with self.assertRaises(exception.GetQueryResultsException) as ex:
            AwsAthenaAsyncClient(mock_athena).get_query_results(query_id)
        self.assertIn(error_message, ex.exception.args[0])


class TestGetQueryError(TestCase):
    def test_get_query_error(self) -> None:
        query_id = "5789-3472-6589"
        error = "FAILED: SemanticException [Error 10072]: Database does not exist: 1234"
        mock_athena = Mock(get_query_execution=Mock(return_value=queries_results.DROP_DATABASE_EXECUTION_FAILURE))
        self.assertEqual(error, AwsAthenaAsyncClient(mock_athena).get_query_error(query_id))
        mock_athena.get_query_execution.assert_called_once_with(QueryExecutionId=query_id)


class TestListTables(TestCase):
    def list_table_metadata(self, CatalogName: str, DatabaseName: str) -> Dict[Any, Any]:
        response_mappings = {
            ("AwsDataCatalog", "some_database"): lambda: {
                "TableMetadataList": [{"Name": "some_table"}, {"Name": "some_other_table"}]
            },
            ("AwsDataCatalog", "empty_database"): lambda: {"TableMetadataList": []},
            ("AwsDataCatalog", "unknown_database"): lambda: _raise(
                ClientError(
                    operation_name="ListTableMetadata",
                    error_response={"Error": {"Code": "MetadataException", "Message": "Database not found."}},
                )
            ),
        }
        return response_mappings.get((CatalogName, DatabaseName))()  # type: ignore

    def get_client(self) -> AwsAthenaAsyncClient:
        return AwsAthenaAsyncClient(Mock(list_table_metadata=Mock(side_effect=self.list_table_metadata)))

    def test_list_tables_success(self) -> None:
        self.assertEqual(["some_table", "some_other_table"], self.get_client().list_tables("some_database"))

    def test_list_tables_empty(self) -> None:
        self.assertEqual([], self.get_client().list_tables("empty_database"))

    def test_list_tables_error(self) -> None:
        with self.assertRaises(exception.ListTablesException):
            self.get_client().list_tables("unknown_database")


class TestListDatabases(TestCase):
    def list_databases(self, CatalogName: str) -> Dict[Any, Any]:
        response_mappings = {
            "CatalogWithDBs": lambda: {"DatabaseList": [{"Name": "some_db"}, {"Name": "some_other_db"}]},
            "EmptyCatalog": lambda: {"DatabaseList": []},
            "BrokenCatalog": lambda: _raise(
                ClientError(
                    operation_name="ListDatabases",
                    error_response={"Error": {"Code": "MetadataException", "Message": "Catalog not found."}},
                )
            ),
        }
        return response_mappings.get(CatalogName)()  # type: ignore

    def get_client(self, catalog: str) -> AwsAthenaAsyncClient:
        client = AwsAthenaAsyncClient(Mock(list_databases=Mock(side_effect=self.list_databases)))
        client._catalog = catalog
        return client

    def test_list_databases_success(self) -> None:
        self.assertEqual(["some_db", "some_other_db"], self.get_client("CatalogWithDBs").list_databases())

    def test_list_databases_empty(self) -> None:
        self.assertEqual([], self.get_client("EmptyCatalog").list_databases())

    def test_list_databases_error(self) -> None:
        with self.assertRaises(exception.ListTablesException):
            self.get_client("BrokenCatalog").list_databases()
