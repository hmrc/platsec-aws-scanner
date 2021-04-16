from logging import getLogger
from typing import List, Optional, Tuple

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from src.data.aws_organizations_types import Account, OrganizationalUnit
from src.aws_scanner_config import AwsScannerConfig as Config


class AwsOrganizationsClient:
    def __init__(self, boto_organizations: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._orgs = boto_organizations

    def find_account_by_id(self, account_id: str) -> Optional[Account]:
        try:
            return Account.to_account(self._orgs.describe_account(AccountId=account_id)["Account"])
        except (BotoCoreError, ClientError) as error:
            self._logger.error(f"account with id {account_id} not found: {error}")
            return None

    def find_account_by_ids(self, account_ids: List[str]) -> List[Account]:
        return list(filter(None, [self.find_account_by_id(account_id) for account_id in account_ids]))

    def get_organization_tree(self) -> List[OrganizationalUnit]:
        self._logger.info("walking the organization tree")
        return self._expand(self._list_roots())

    def get_all_accounts(self) -> List[Account]:
        return [
            account
            for org_unit in self._flatten_org_units(self.get_organization_tree())
            for account in org_unit.accounts
        ]

    def get_target_accounts(self) -> List[Account]:
        target_accounts = [
            account
            for org_unit in self._flatten_org_units(
                self._filter_by_name(self.get_organization_tree(), Config().org_unit_parent())
            )
            for account in org_unit.accounts
        ]
        if Config().org_unit_include_root_accounts():
            target_accounts.extend([account for root in self._list_roots() for account in root.accounts])
        return target_accounts

    def _filter_by_name(
        self, ous: List[OrganizationalUnit], name: str, filtered: Optional[List[OrganizationalUnit]] = None
    ) -> List[OrganizationalUnit]:
        filtered = [] if filtered is None else filtered
        for ou in ous:
            filtered.append(ou) if ou.name == name else self._filter_by_name(ou.org_units, name, filtered)
        return filtered

    def _list_roots(self) -> List[OrganizationalUnit]:
        self._logger.debug("listing roots for organization")
        return [
            self._load_accounts(OrganizationalUnit.to_root_org_unit(root)) for root in self._orgs.list_roots()["Roots"]
        ]

    def _list_accounts(self, ou: OrganizationalUnit, next_token: Optional[str] = None) -> Tuple[str, List[Account]]:
        self._logger.debug(f"listing accounts for {ou}")
        response = (
            self._orgs.list_accounts_for_parent(ParentId=ou.identifier, NextToken=next_token)
            if next_token
            else self._orgs.list_accounts_for_parent(ParentId=ou.identifier)
        )
        return response["NextToken"] if "NextToken" in response else "", [
            Account.to_account(account) for account in response["Accounts"]
        ]

    def _list_org_units_for_parent(self, org_unit: OrganizationalUnit) -> List[OrganizationalUnit]:
        self._logger.debug(f"listing organizational units for {org_unit}")
        return [
            OrganizationalUnit.to_org_unit(ou)
            for ou in self._orgs.list_organizational_units_for_parent(ParentId=org_unit.identifier)[
                "OrganizationalUnits"
            ]
        ]

    def _expand(self, org_units: List[OrganizationalUnit]) -> List[OrganizationalUnit]:
        for ou in org_units:
            self._expand_organizational_units(ou)
        return org_units

    def _expand_organizational_units(self, org_unit: OrganizationalUnit) -> None:
        org_unit.org_units = self._list_org_units_for_parent(org_unit)
        for ou in org_unit.org_units:
            self._expand_organizational_units(ou)
            self._load_accounts(ou)

    def _load_accounts(self, org_unit: OrganizationalUnit) -> OrganizationalUnit:
        next_token, accounts = self._list_accounts(org_unit)
        org_unit.accounts.extend(accounts)
        while next_token:
            next_token, accounts = self._list_accounts(org_unit, next_token)
            org_unit.accounts.extend(accounts)
        return org_unit

    @staticmethod
    def _flatten_org_units(org_units: List[OrganizationalUnit]) -> List[OrganizationalUnit]:
        return [ou for org_unit in org_units for ou in AwsOrganizationsClient._flatten_org_unit(org_unit)]

    @staticmethod
    def _flatten_org_unit(org_unit: OrganizationalUnit) -> List[OrganizationalUnit]:
        flat_ous = []
        for ou in org_unit.org_units:
            flat_ous.extend(AwsOrganizationsClient._flatten_org_unit(ou))
        flat_ous.append(org_unit)
        return flat_ous
