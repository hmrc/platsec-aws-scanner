from tests.aws_scanner_test_case import AwsScannerTestCase

from src.json_serializer import to_json

from tests.test_types_generator import task_report


class TestJsonSerializer(AwsScannerTestCase):
    def test_serialize_complex_object_with_optional_properties(self) -> None:
        self.assertEqual(
            (
                '{"account": {"identifier": "account_id", "name": "account_name"}, "description": "task", '
                '"results": {"key": "val"}}'
            ),
            to_json(task_report(partition=None)),
        )
