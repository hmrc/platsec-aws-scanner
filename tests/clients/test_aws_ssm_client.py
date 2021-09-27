from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from typing import Any, Dict

from src.data.aws_scanner_exceptions import ListSSMParametersException
from src.clients.aws_ssm_client import AwsSSMClient

from tests.clients import test_aws_ssm_client_responses as responses
from tests.test_types_generator import client_error


class TestAwsSSMClient(AwsScannerTestCase):
    def test_list_parameters(self) -> None:
        self.assertEqual(responses.EXPECTED_LIST_PARAMETERS, self.get_ssm_client().list_parameters())

    def get_ssm_client(self) -> AwsSSMClient:
        return AwsSSMClient(Mock(describe_parameters=Mock(side_effect=self.describe_parameters)))

    def describe_parameters(self, **kwargs: Dict[str, Any]) -> Dict[Any, Any]:
        self.assertEqual(50, kwargs["MaxResults"], f"expected MaxResults=50, got {kwargs['MaxResults']}")
        self.assertEqual([{"Key": "Path", "Option": "Recursive", "Values": ["/"]}], kwargs["ParameterFilters"])

        if "NextToken" in kwargs and str(kwargs["NextToken"]) == "token_for_params_page_2":
            return responses.DESCRIBE_PARAMETERS_PAGE_2
        else:
            return responses.DESCRIBE_PARAMETERS_PAGE_1


class TestAwsSSMClientFailure(AwsScannerTestCase):
    def test_list_parameters_failure(self) -> None:
        with self.assertRaisesRegex(ListSSMParametersException, "SomeErrorCode"):
            self.get_ssm_client().list_parameters()

    def get_ssm_client(self) -> AwsSSMClient:
        return AwsSSMClient(Mock(describe_parameters=Mock(side_effect=self.describe_parameters)))

    @staticmethod
    def describe_parameters(**kwargs: Dict[str, Any]) -> Dict[Any, Any]:
        raise client_error("describe_parameters", "SomeErrorCode", "Unable to describe SSM parameters")
