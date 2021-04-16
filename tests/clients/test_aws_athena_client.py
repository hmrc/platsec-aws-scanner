from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, call, patch

from typing import Any, Dict, Type

from src.data import aws_scanner_exceptions as exceptions
from src.clients.aws_athena_client import AwsAthenaClient

from tests.test_types_generator import account, partition


@patch.object(AwsAthenaClient, "_get_default_delay", return_value=0)
class TestWaitFor(AwsScannerTestCase):
    def test_wait_for_completion(self, _: Mock) -> None:
        query_id = "8759-2768-2364"
        mock_has_query_completed = Mock(side_effect=[False, False, True])
        with patch(
            "src.clients.aws_athena_async_client.AwsAthenaAsyncClient.has_query_completed", mock_has_query_completed
        ):
            AwsAthenaClient(Mock())._wait_for_completion(query_id, 60)
        mock_has_query_completed.assert_has_calls([call(query_id) for _ in range(3)])

    def test_wait_for_completion_timeout(self, _: Mock) -> None:
        query_id = "9837-4857-3576"
        mock_has_query_completed = Mock(return_value=False)
        with patch(
            "src.clients.aws_athena_async_client.AwsAthenaAsyncClient.has_query_completed", mock_has_query_completed
        ):
            with self.assertRaises(exceptions.TimeoutException) as ex:
                AwsAthenaClient(Mock())._wait_for_completion(query_id, 30)
        mock_has_query_completed.assert_has_calls([call(query_id) for _ in range(30)])
        self.assertIn(query_id, ex.exception.args[0])

    def test_wait_for_success(self, _: Mock) -> None:
        query_id = "9847-2919-2284"
        timeout = 74
        query_results = ["some results"]
        mock_wait_for_completion = Mock(return_value=None)
        mock_query_succeeded = Mock(return_value=True)
        mock_query_results = Mock(return_value=query_results)
        with patch("src.clients.aws_athena_client.AwsAthenaClient._wait_for_completion", mock_wait_for_completion):
            with patch(
                "src.clients.aws_athena_async_client.AwsAthenaAsyncClient.has_query_succeeded", mock_query_succeeded
            ):
                with patch(
                    "src.clients.aws_athena_async_client.AwsAthenaAsyncClient.get_query_results", mock_query_results
                ):
                    actual_results = AwsAthenaClient(Mock())._wait_for_success(query_id, timeout, Exception)
        self.assertEqual(query_results, actual_results)
        mock_wait_for_completion.assert_called_once_with(query_id, timeout)
        mock_query_succeeded.assert_called_once_with(query_id)

    def test_wait_for_success_query_does_not_succeed(self, _: Mock) -> None:
        mock_wait_for_completion = Mock(return_value=None)
        mock_query_succeeded = Mock(return_value=False)
        query_error = "the query failed for some reasons"
        mock_get_query_error = Mock(return_value=query_error)
        with patch("src.clients.aws_athena_client.AwsAthenaClient._wait_for_completion", mock_wait_for_completion):
            with patch(
                "src.clients.aws_athena_async_client.AwsAthenaAsyncClient.has_query_succeeded", mock_query_succeeded
            ):
                with patch(
                    "src.clients.aws_athena_async_client.AwsAthenaAsyncClient.get_query_error", mock_get_query_error
                ):
                    with self.assertRaises(exceptions.RunQueryException) as ex:
                        AwsAthenaClient(Mock())._wait_for_success("9847-2919-2284", 74, exceptions.RunQueryException)
        self.assertIn(query_error, ex.exception.args)


@patch("src.clients.aws_athena_client.AwsAthenaClient._wait_for_success")
class TestQueries(AwsScannerTestCase):
    def test_create_database(self, mock_wait_for_success: Mock) -> None:
        self.assert_wait_for_success(
            mock_wait_for_success=mock_wait_for_success,
            method_under_test="create_database",
            method_args={"database_name": "some_db_name"},
            timeout_seconds=60,
            raise_on_failure=exceptions.CreateDatabaseException,
        )

    def test_drop_database(self, mock_wait_for_success: Mock) -> None:
        self.assert_wait_for_success(
            mock_wait_for_success=mock_wait_for_success,
            method_under_test="drop_database",
            method_args={"database_name": "some_db_name"},
            timeout_seconds=60,
            raise_on_failure=exceptions.DropDatabaseException,
        )

    def test_create_table(self, mock_wait_for_success: Mock) -> None:
        self.assert_wait_for_success(
            mock_wait_for_success=mock_wait_for_success,
            method_under_test="create_table",
            method_args={"database": "some_db", "account": account()},
            timeout_seconds=60,
            raise_on_failure=exceptions.CreateTableException,
        )

    def test_drop_table(self, mock_wait_for_success: Mock) -> None:
        self.assert_wait_for_success(
            mock_wait_for_success=mock_wait_for_success,
            method_under_test="drop_table",
            method_args={"database": "some_db", "table": "some_account_id"},
            timeout_seconds=60,
            raise_on_failure=exceptions.DropTableException,
        )

    def test_add_partition(self, mock_wait_for_success: Mock) -> None:
        self.assert_wait_for_success(
            mock_wait_for_success=mock_wait_for_success,
            method_under_test="add_partition",
            method_args={
                "database": "some_db",
                "account": account(),
                "partition": partition(2019, 8),
            },
            timeout_seconds=120,
            raise_on_failure=exceptions.AddPartitionException,
        )

    def test_run_query(self, mock_wait_for_success: Mock) -> None:
        self.assert_wait_for_success(
            mock_wait_for_success=mock_wait_for_success,
            method_under_test="run_query",
            method_args={"database": "some_db", "query": "SELECT something FROM somewhere"},
            timeout_seconds=300,
            raise_on_failure=exceptions.RunQueryException,
            return_results=True,
        )

    def assert_wait_for_success(
        self,
        mock_wait_for_success: Mock,
        method_under_test: str,
        method_args: Dict[str, Any],
        timeout_seconds: int,
        raise_on_failure: Type[Exception],
        return_results: bool = False,
    ) -> None:
        query_id = "1536-4938-3968"
        query_results = ["some query results"]
        mock_wait_for_success.return_value = query_results
        mock_method_under_test = Mock(return_value=query_id)
        with patch(f"src.clients.aws_athena_client.AwsAthenaAsyncClient.{method_under_test}", mock_method_under_test):
            actual_results = getattr(AwsAthenaClient(Mock()), method_under_test)(**method_args)
        mock_method_under_test.assert_called_once_with(**method_args)
        mock_wait_for_success.assert_called_once_with(
            query_id=query_id,
            timeout_seconds=timeout_seconds,
            raise_on_failure=raise_on_failure,
        )
        if return_results:
            self.assertEqual(query_results, actual_results)


class TestDefaultDelay(AwsScannerTestCase):
    def test_default_delay_is_one_second(self) -> None:
        self.assertEqual(1, AwsAthenaClient(Mock())._get_default_delay())


class TestList(AwsScannerTestCase):
    def test_list_databases(self) -> None:
        dbs = ["db1", "db2", "db3"]
        mock_athena_async = Mock(list_databases=Mock(return_value=dbs))
        client = AwsAthenaClient(Mock())
        with patch.object(client, "_athena_async", mock_athena_async):
            self.assertEqual(dbs, client.list_databases())

    def test_list_tables(self) -> None:
        tables = ["table1", "table2", "table3"]
        mock_athena_async = Mock(list_tables=Mock(side_effect=lambda db: tables if db == "some_database" else []))
        client = AwsAthenaClient(Mock())
        with patch.object(client, "_athena_async", mock_athena_async):
            self.assertEqual(tables, client.list_tables("some_database"))
