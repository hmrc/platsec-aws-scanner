from unittest import TestCase
from unittest.mock import Mock

from tests.test_types_generator import ssm_task


class TestAwsSSMTask(TestCase):
    def test_run_task(self) -> None:
        with self.assertRaises(NotImplementedError):
            ssm_task()._run_task(Mock())
