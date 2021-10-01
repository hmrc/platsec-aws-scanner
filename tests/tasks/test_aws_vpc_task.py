from unittest import TestCase
from unittest.mock import Mock

from tests.test_types_generator import vpc_task


class TestAwsVpcTask(TestCase):
    def test_run_task(self) -> None:
        with self.assertRaises(NotImplementedError):
            vpc_task()._run_task(Mock())
