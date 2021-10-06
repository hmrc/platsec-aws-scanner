from unittest import TestCase
from unittest.mock import Mock

from tests.test_types_generator import account, partition, task_report


class GenericCloudTrailTestCase(TestCase):
    @staticmethod
    def __build_task_under_test(task_type, task_args):  # type: ignore
        task = task_type(account=account(), partition=partition(), **task_args)
        task._database = "some_db"
        return task

    def _assert_task_run(self, task_type, task_args, query, query_results, results) -> None:  # type: ignore
        for task_index, query_result in enumerate(query_results):
            athena = Mock(run_query=Mock(return_value=query_result))
            task = self.__build_task_under_test(task_type=task_type, task_args=task_args)  # type: ignore
            self.assertEqual(task_report(description=task._description, results=results[task_index]), task.run(athena))
            athena.run_query.assert_called_once_with(database="some_db", query=query)
