from unittest import TestCase
from unittest.mock import Mock

from tests.test_types_generator import cloudtrail_task


class TestAwsCloudTrailTask(TestCase):
    def test_create_table(self) -> None:
        task = cloudtrail_task()
        client = Mock()
        task._create_table(client)
        client.create_table.assert_called_once_with(task._database, task._account)

    def test_create_partition(self) -> None:
        task = cloudtrail_task()
        client = Mock()
        task._create_partition(client)
        client.add_partition.assert_called_once_with(task._database, task._account, task._partition)

    def test_run_task(self) -> None:
        with self.assertRaises(NotImplementedError):
            cloudtrail_task()._run_task(Mock())
