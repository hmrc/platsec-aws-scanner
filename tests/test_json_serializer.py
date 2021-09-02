from tests.aws_scanner_test_case import AwsScannerTestCase

from src.json_serializer import to_json

from tests.test_types_generator import create_flow_log_action, task_report


class TestJsonSerializer(AwsScannerTestCase):
    def test_serialize_complex_object_with_optional_properties(self) -> None:
        self.assertEqual(
            (
                '{"account": {"identifier": "account_id", "name": "account_name"}, "description": "task", '
                '"results": {"key": "val"}}'
            ),
            to_json(task_report(partition=None)),
        )

    def test_serialize_exclude_callable_properties(self) -> None:
        self.assertEqual(
            '{"description": "Create VPC flow log", "status": "not applied", "vpc_id": "2", "log_group_name": "z"}',
            to_json(create_flow_log_action(vpc_id="2", log_group_name="z", permission_resolver=lambda: "thing")),
        )
