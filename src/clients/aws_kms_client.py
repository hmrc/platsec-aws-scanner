from json import loads
from logging import getLogger

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError
from typing import Any, Dict, Optional

from src.data.aws_scanner_exceptions import KmsException
from src.data.aws_kms_types import Key, to_key


class AwsKmsClient:
    def __init__(self, boto_kms: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._kms = boto_kms

    def find_key(self, key_id: str) -> Optional[Key]:
        try:
            return self._enrich_key(self._describe_key(key_id))
        except KmsException as ex:
            self._logger.warning(f"unable to find key with id '{key_id}': {ex}")
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
            return dict(loads(self._kms.get_key_policy(KeyId=key_id)["Policy"]))
        except (BotoCoreError, ClientError) as err:
            raise KmsException(f"unable to get policy for kms key with id '{key_id}': {err}") from None
