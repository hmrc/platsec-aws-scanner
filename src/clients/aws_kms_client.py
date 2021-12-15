from json import loads
from logging import getLogger

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError
from typing import Any, Dict, Optional, Sequence

from src.data.aws_scanner_exceptions import KmsException
from src.data.aws_kms_types import Key, to_key
from src.data.aws_common_types import Tag


class AwsKmsClient:
    _kms: BaseClient

    def __init__(self, boto_kms: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._kms = boto_kms

    def get_key(self, key_id: str) -> Key:
        return self._enrich_key(self._describe_key(key_id))

    def find_key(self, key_id: str) -> Optional[Key]:
        try:
            return self.get_key(key_id)
        except KmsException as ex:
            self._logger.warning(ex)
            return None

    def _enrich_key(self, key: Key) -> Key:
        key.policy = self._get_key_policy(key.id)
        key.tags = self._list_resource_tags(key.id)
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

    def _list_resource_tags(self, key_id: str) -> Sequence[Tag]:
        try:
            return list(
                map(
                    lambda tag: Tag(key=tag["TagKey"], value=tag["TagValue"]),
                    self._kms.list_resource_tags(KeyId=key_id)["Tags"],
                )
            )
        except (BotoCoreError, ClientError) as err:
            raise KmsException(f"unable to list tags for kms key '{key_id}': {err}") from None
