from unittest import TestCase

from src.data.aws_ssm_types import Parameter, to_parameter


class TestAwsSSMTypes(TestCase):
    def test_to_string_parameter(self) -> None:
        parameter = {"Name": "a_string_param", "Type": "String"}
        self.assertEqual(Parameter(name="a_string_param", type="String"), to_parameter(parameter))

    def test_to_secure_string_parameter(self) -> None:
        parameter = {"Name": "a_secure_string_param", "Type": "SecureString"}
        self.assertEqual(Parameter(name="a_secure_string_param", type="SecureString"), to_parameter(parameter))
