from unittest import TestCase
from unittest.mock import Mock

from typing import Any, Dict

from src.data.aws_scanner_exceptions import GetSSMDocumentException, ListSSMParametersException
from src.clients.aws_ssm_client import AwsSSMClient
from src.data.aws_ssm_types import SSMDocument
from src.tasks.aws_audit_ssm_document_task import SESSION_MANAGER_RUN_SHELL_DOCUMENT_NAME

from tests.clients import test_aws_ssm_client_responses as responses
from tests.test_types_generator import client_error


class TestAwsSSMClient(TestCase):
    def test_list_parameters(self) -> None:
        self.assertEqual(responses.EXPECTED_LIST_PARAMETERS, self.get_ssm_client().list_parameters())

    def test_get_document(self) -> None:
        self.assertEqual(responses.EXPECTED_SSM_DOCUMENT, self.get_ssm_client().get_document(name=SESSION_MANAGER_RUN_SHELL_DOCUMENT_NAME))

    def get_ssm_client(self) -> AwsSSMClient:
        return AwsSSMClient(Mock(
            describe_parameters=Mock(side_effect=self.describe_parameters),
            get_document=Mock(return_value=responses.RESPONSE_GET_DOCUMENT),
        ))

    def describe_parameters(self, **kwargs: Dict[str, Any]) -> Dict[Any, Any]:
        self.assertEqual(50, kwargs["MaxResults"], f"expected MaxResults=50, got {kwargs['MaxResults']}")
        self.assertEqual([{"Key": "Path", "Option": "Recursive", "Values": ["/"]}], kwargs["ParameterFilters"])

        if "NextToken" in kwargs and str(kwargs["NextToken"]) == "token_for_params_page_2":
            return responses.DESCRIBE_PARAMETERS_PAGE_2
        else:
            return responses.DESCRIBE_PARAMETERS_PAGE_1


class TestAwsSSMClientFailure(TestCase):
    def test_list_parameters_failure(self) -> None:
        with self.assertRaisesRegex(ListSSMParametersException, "SomeErrorCode"):
            self.get_ssm_client().list_parameters()

    def test_get_document_failure(self) -> None:
        with self.assertRaisesRegex(GetSSMDocumentException, "SomeErrorCode"):
            self.get_ssm_client().get_document(name='someDoc')

    def get_ssm_client(self) -> AwsSSMClient:
        return AwsSSMClient(Mock(
            describe_parameters=Mock(side_effect=self.describe_parameters),
            get_document=Mock(side_effect=self.get_document),
        ))

    @staticmethod
    def describe_parameters(**kwargs: Dict[str, Any]) -> Dict[Any, Any]:
        raise client_error("describe_parameters", "SomeErrorCode", "Unable to describe SSM parameters")

    @staticmethod
    def get_document(**kwargs: Dict[str, str]) -> Dict[str, Any]:
        raise client_error("get_document", "SomeErrorCode", "Unable to get SSM document")
