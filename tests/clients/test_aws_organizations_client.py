# type: ignore
from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, patch

from typing import Any, Dict

from botocore.exceptions import ParamValidationError

from src.clients.aws_organizations_client import AwsOrganizationsClient

from tests.clients import test_aws_organizations_client_responses as responses
from tests.test_types_generator import account


class TestAwsOrganizationsClient(AwsScannerTestCase):
    def test_find_account_by_id(self) -> None:
        account_id = "123456789012"
        mock_boto_orgs = Mock(
            describe_account=Mock(
                side_effect=lambda AccountId: responses.DESCRIBE_ACCOUNT if AccountId == account_id else None
            )
        )
        self.assertEqual(
            account(account_id, "some test account"),
            AwsOrganizationsClient(mock_boto_orgs).find_account_by_id(account_id),
        )

    def test_account_not_found(self) -> None:
        account_id = "123456789012"
        error_msg = "boom"
        mock_boto_orgs = Mock(describe_account=Mock(side_effect=ParamValidationError(report=error_msg)))
        with self.assertLogs("AwsOrganizationsClient", level="ERROR") as error_log:
            AwsOrganizationsClient(mock_boto_orgs).find_account_by_id(account_id)
        self.assertIn(account_id, error_log.output[0])
        self.assertIn(error_msg, error_log.output[0])

    def test_find_account_by_ids(self) -> None:
        with patch(
            "src.clients.aws_organizations_client.AwsOrganizationsClient.find_account_by_id",
            side_effect=lambda acc_id: {
                "3": account("3", "account 3"),
                "8": account("8", "account 8"),
                "2": None,
                "5": account("5", "account 5"),
            }.get(acc_id),
        ):
            self.assertEqual(
                [account("8", "account 8"), account("5", "account 5"), account("3", "account 3")],
                AwsOrganizationsClient(Mock()).find_account_by_ids(["8", "2", "5", "3"]),
            )

    def test_get_organization_tree(self) -> None:
        self.assertEqual(responses.EXPECTED_ORGANIZATION_TREE, self.get_org_client().get_organization_tree())

    def test_get_all_accounts(self) -> None:
        self.assertEqual(responses.EXPECTED_ALL_ACCOUNTS, self.get_org_client().get_all_accounts())

    def test_get_target_accounts_includes_root(self) -> None:
        with patch("src.aws_scanner_config.AwsScannerConfig.organization_parent", return_value="Root 1 > Org Unit 2"):
            self.assertEqual(responses.EXPECTED_TARGET_ACCOUNTS, self.get_org_client().get_target_accounts())

    def test_get_target_accounts_not_includes_root(self) -> None:
        with patch("src.aws_scanner_config.AwsScannerConfig.organization_parent", return_value="Root 1 > Org Unit 2"):
            with patch(
                "src.aws_scanner_config.AwsScannerConfig.organization_include_root_accounts", return_value=False
            ):
                self.assertEqual(
                    responses.EXPECTED_TARGET_ACCOUNTS_WITHOUT_ROOT, self.get_org_client().get_target_accounts()
                )

    def get_org_client(self) -> AwsOrganizationsClient:
        return AwsOrganizationsClient(
            Mock(
                list_roots=Mock(side_effect=self.list_roots),
                list_organizational_units_for_parent=Mock(side_effect=self.list_organizational_units_for_parent),
                list_accounts_for_parent=Mock(side_effect=self.list_accounts_for_parent),
            )
        )

    @staticmethod
    def list_roots() -> Dict[Any, Any]:
        return responses.ROOTS

    @staticmethod
    def list_organizational_units_for_parent(**kwargs) -> Dict[Any, Any]:
        if kwargs["ParentId"] == "r-root1":
            return responses.ORG_UNITS_FOR_ROOT
        if kwargs["ParentId"] == "ou-root1-2":
            return responses.ORG_UNITS_FOR_ORG_UNIT_2
        return responses.EMPTY_ORG_UNITS

    @staticmethod
    def list_accounts_for_parent(**kwargs) -> Dict[Any, Any]:
        if kwargs["ParentId"] == "ou-root1-1":
            if "NextToken" in kwargs and kwargs["NextToken"] == "root-1-org-unit-1-next-token":
                return responses.ACCOUNTS_FOR_ORG_UNIT_1_PAGE_2
            return responses.ACCOUNTS_FOR_ORG_UNIT_1_PAGE_1
        elif kwargs["ParentId"] == "ou-root1-2":
            return responses.ACCOUNTS_FOR_ORG_UNIT_2
        elif kwargs["ParentId"] == "ou-root1-2-2":
            return responses.ACCOUNTS_FOR_ORG_UNIT_2_2
        elif kwargs["ParentId"] == "r-root1":
            return responses.ACCOUNTS_FOR_ROOT_1
        return responses.EMPTY_ACCOUNTS
