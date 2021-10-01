from unittest import TestCase
from unittest.mock import Mock

from src.tasks.aws_list_ssm_parameters_task import AwsListSSMParametersTask

from tests.test_types_generator import account, secure_string_parameter, string_list_parameter, string_parameter


class TestAwsListSSMParametersTask(TestCase):
    def test_run_task(self) -> None:
        parameters = [
            secure_string_parameter("secure_1"),
            string_list_parameter("list"),
            string_parameter("string_1"),
            secure_string_parameter("secure_2"),
            string_parameter("string_2"),
            string_parameter("string_3"),
        ]
        ssm_client = Mock(list_parameters=Mock(return_value=parameters))
        task_report = AwsListSSMParametersTask(account())._run_task(ssm_client)
        self.assertEqual(
            {
                "ssm_parameters": parameters,
                "type_count": {"SecureString": 2, "StringList": 1, "String": 3},
                "total_count": 6,
            },
            task_report,
        )
