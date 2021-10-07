from json import dumps, loads
from logging import getLogger

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError
from typing import Any, Dict, Optional, Sequence

from src.data.aws_scanner_exceptions import KmsException
from src.data.aws_kms_types import Alias, Key, to_alias, to_key


class AwsKmsClient:
    _kms: BaseClient

    def __init__(self, boto_kms: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._kms = boto_kms

    def get_key(self, key_id: str) -> Key:
        return self._enrich_key(self._describe_key(key_id))

    def get_alias(self, alias_name: str) -> Alias:
        try:
            return next(filter(lambda a: a.name == f"alias/{alias_name}", self._list_aliases()))
        except StopIteration:
            raise KmsException(f"unable to get alias with name '{alias_name}'") from None

    def find_alias(self, alias_name: str) -> Optional[Alias]:
        try:
            return self.get_alias(alias_name)
        except KmsException:
            return None

    def _enrich_key(self, key: Key) -> Key:
        key.policy = self._get_key_policy(key.id)
        return key

    def _describe_key(self, key_id: str) -> Key:
        try:
            return to_key(self._kms.describe_key(KeyId=key_id)["KeyMetadata"])
        except (BotoCoreError, ClientError) as err:
            raise KmsException(f"unable to describe kms key with id '{key_id}': {err}") from None

    def _get_key_policy(self, key_id: str) -> Dict[str, Any]:
        try:
            return dict(loads(self._kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]))
        except (BotoCoreError, ClientError) as err:
            raise KmsException(f"unable to get policy for kms key with id '{key_id}': {err}") from None

    def create_key(self, alias: str, description: str) -> Key:
        try:
            key = to_key(
                self._kms.create_key(
                    Description=description,
                    Tags=[
                        {"TagKey": "allow-key-management-by-platsec-scanner", "TagValue": "true"},
                        {"TagKey": "src-repo", "TagValue": "https://github.com/hmrc/platsec-aws-scanner"},
                    ],
                )["KeyMetadata"]
            )
        except (BotoCoreError, ClientError) as err:
            raise KmsException(f"unable to create kms key with description '{description}': {err}") from None

        self._create_alias(key.id, alias)
        return key

    def _create_alias(self, key_id: str, alias: str) -> None:
        try:
            self._kms.create_alias(TargetKeyId=key_id, AliasName=f"alias/{alias}")
        except (BotoCoreError, ClientError) as err:
            raise KmsException(f"unable to create alias '{alias}' for key '{key_id}': {err}") from None

    def put_key_policy_statements(self, key_id: str, statements: Sequence[Dict[str, Any]]) -> None:
        policy = {"Version": "2008-10-17", "Statement": statements}

        try:
            self._kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=dumps(policy))
        except (BotoCoreError, ClientError) as err:
            raise KmsException(f"unable to put policy '{policy}' for key '{key_id}': {err}") from None

    def _list_aliases(self) -> Sequence[Alias]:
        try:
            return [to_alias(a) for page in self._kms.get_paginator("list_aliases").paginate() for a in page["Aliases"]]
        except (BotoCoreError, ClientError) as err:
            raise KmsException(f"unable to list kms key aliases: {err}") from None

    def delete_alias(self, name: str) -> None:
        target_name = f"alias/{name}"
        try:
            self._kms.delete_alias(AliasName=target_name)
        except (BotoCoreError, ClientError) as err:
            raise KmsException(f"unable to delete kms key alias named '{target_name}': {err}") from None
