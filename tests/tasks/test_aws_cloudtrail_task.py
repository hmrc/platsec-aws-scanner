from unittest import TestCase
from unittest.mock import Mock

from src.clients.aws_athena_client import AwsAthenaClient
from tests.clients.test_aws_athena_cloudtrail_queries import ADD_PARTITION_YEAR_MONTH, CREATE_TABLE
from src.data.aws_scanner_exceptions import AddPartitionException, CreateTableException

from tests.test_types_generator import cloudtrail_task


class TestAwsCloudTrailTask(TestCase):
    def test_create_table(self) -> None:
        task = cloudtrail_task()
        client = Mock(spec=AwsAthenaClient)
        task._create_table(client)
        client.run_query.assert_called_once_with(
            database=task._database,
            query=CREATE_TABLE,
            raise_on_failure=CreateTableException,
        )

    def test_create_partition(self) -> None:
        task = cloudtrail_task()
        client = Mock(spec=AwsAthenaClient)
        task._create_partition(client)
        client.run_query.assert_called_once_with(
            database=task._database,
            query=ADD_PARTITION_YEAR_MONTH,
            raise_on_failure=AddPartitionException,
        )

    def test_run_task(self) -> None:
        with self.assertRaises(NotImplementedError):
            cloudtrail_task()._run_task(Mock())
