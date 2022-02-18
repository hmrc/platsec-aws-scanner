from unittest import TestCase
from unittest.mock import Mock

from src.clients.aws_athena_cloudtrail_queries import ADD_PARTITION_YEAR_MONTH, CREATE_TABLE

from tests.test_types_generator import cloudtrail_task


class TestAwsCloudTrailTask(TestCase):
    def test_create_table(self) -> None:
        task = cloudtrail_task()
        client = Mock()
        task._create_table(client)
        client.create_table.assert_called_once_with(
            database=task._database,
            table=task._account.identifier,
            query_template=CREATE_TABLE,
            query_attributes={"account": task._account.identifier, "cloudtrail_logs_bucket": "cloudtrail-logs-bucket"},
        )

    def test_create_partition(self) -> None:
        task = cloudtrail_task()
        client = Mock()
        task._create_partition(client)
        client.add_partition.assert_called_once_with(
            database=task._database,
            table=task._account.identifier,
            query_template=ADD_PARTITION_YEAR_MONTH,
            query_attributes={
                "account": task._account.identifier,
                "region": task._partition.region,
                "year": task._partition.year,
                "month": task._partition.month,
                "cloudtrail_logs_bucket": "cloudtrail-logs-bucket",
            },
        )

    def test_run_task(self) -> None:
        with self.assertRaises(NotImplementedError):
            cloudtrail_task()._run_task(Mock())
