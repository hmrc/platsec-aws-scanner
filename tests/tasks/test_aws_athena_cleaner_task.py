from unittest import TestCase
from unittest.mock import Mock, call

from src.tasks.aws_athena_cleaner_task import AwsAthenaCleanerTask

from tests.test_types_generator import account, task_report


class TestAwsAthenaCleanerTask(TestCase):
    database_mappings = {
        "db_1": ["table_1", "table_2", "table_3"],
        "some_prefix_db_2": ["table_1", "table_2"],
        "db_3": ["table_1"],
        "some_prefix_db_4": ["table_1", "table_2", "table_3"],
        "some_prefix_db_5": [],
    }
    expected_report = task_report(
        account=account("555666777888", "athena"),
        description="clean scanner leftovers",
        partition=None,
        results={
            "dropped_tables": [
                "some_prefix_db_2.table_1",
                "some_prefix_db_2.table_2",
                "some_prefix_db_4.table_1",
                "some_prefix_db_4.table_2",
                "some_prefix_db_4.table_3",
            ],
            "dropped_databases": ["some_prefix_db_2", "some_prefix_db_4", "some_prefix_db_5"],
        },
    )

    def test_clean_task_databases(self) -> None:
        mock_athena = Mock(
            list_databases=Mock(return_value=list(self.database_mappings.keys())),
            list_tables=Mock(side_effect=lambda db: self.database_mappings.get(db)),
        )
        self.assertEqual(self.expected_report, AwsAthenaCleanerTask().run(mock_athena))
        mock_athena.assert_has_calls(
            [
                call.list_databases(),
                call.list_tables("some_prefix_db_2"),
                call.drop_table("some_prefix_db_2", "table_1"),
                call.drop_table("some_prefix_db_2", "table_2"),
                call.list_tables("some_prefix_db_4"),
                call.drop_table("some_prefix_db_4", "table_1"),
                call.drop_table("some_prefix_db_4", "table_2"),
                call.drop_table("some_prefix_db_4", "table_3"),
                call.list_tables("some_prefix_db_5"),
                call.drop_database("some_prefix_db_2"),
                call.drop_database("some_prefix_db_4"),
                call.drop_database("some_prefix_db_5"),
            ]
        )
