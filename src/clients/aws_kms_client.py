from json import dumps, loads
from logging import getLogger

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError
from typing import Any, Dict, Sequence

from src.data.aws_scanner_exceptions import KmsException
from src.data.aws_kms_types import Alias, Key, to_alias, to_key


class AwsKmsClient:
    def __init__(self, boto_kms: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._kms = boto_kms

    def get_key(self, key_id: str) -> Key:
        return self._enrich_key(self._describe_key(key_id))

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

    def create_key(self, alias: str, description: str, statements: Sequence[Dict[str, Any]]) -> None:
        try:
            key = to_key(self._kms.create_key(Description=description)["KeyMetadata"])
        except (BotoCoreError, ClientError) as err:
            raise KmsException(f"unable to create kms key with description '{description}': {err}") from None

        self._create_alias(key.id, alias)
        self._put_key_policy_statements(key.id, statements)

    def _create_alias(self, key_id: str, alias: str) -> None:
        try:
            self._kms.create_alias(TargetKeyId=key_id, AliasName=f"alias/{alias}")
        except (BotoCoreError, ClientError) as err:
            raise KmsException(f"unable to create alias '{alias}' for key '{key_id}': {err}") from None

    def _put_key_policy_statements(self, key_id: str, statements: Sequence[Dict[str, Any]]) -> None:
        policy = self._get_key_policy(key_id)
        policy["Statement"].extend(statements)

        try:
            self._kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=dumps(policy))
        except (BotoCoreError, ClientError) as err:
            raise KmsException(f"unable to put policy '{policy}' for key '{key_id}': {err}") from None

    def _list_aliases(self) -> Sequence[Alias]:
        try:
            return [to_alias(a) for page in self._kms.get_paginator("list_aliases").paginate() for a in page["Aliases"]]
        except (BotoCoreError, ClientError) as err:
            raise KmsException(f"unable to list kms key aliases: {err}") from None
