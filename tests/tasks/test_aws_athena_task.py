from unittest import TestCase
from unittest.mock import Mock

from tests.test_types_generator import athena_task


class TestAwsAthenaTask(TestCase):
    def test_run_task(self) -> None:
        with self.assertRaises(NotImplementedError):
            athena_task()._run_task(Mock())
