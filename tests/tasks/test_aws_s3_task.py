from unittest import TestCase
from unittest.mock import Mock

from tests.test_types_generator import s3_task


class TestAwsS3Task(TestCase):
    def test_run_task(self) -> None:
        with self.assertRaises(NotImplementedError):
            s3_task()._run_task(Mock())
