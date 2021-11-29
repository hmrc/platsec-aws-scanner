from logging import getLogger
from typing import Any, Sequence

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from src.data.aws_iam_types import User, AccessKey
from src.data.aws_scanner_exceptions import IamException


class AwsIamAuditClient:
    def __init__(self, boto_iam: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._iam = boto_iam

    def list_users(self) -> Sequence[User]:
        try:
            return [
                User(user_name=user["UserName"])
                for page in self._iam.get_paginator("list_users").paginate()
                for user in page["Users"]
            ]
        except (BotoCoreError, ClientError) as e:
            raise IamException(f"unable to list users: {e}")

    def list_access_keys(self, user: User) -> Sequence[AccessKey]:
        try:
            return [
                AccessKey(user_name=key["UserName"], id=key["AccessKeyId"], created=key["CreateDate"])
                for page in self._iam.get_paginator("list_access_keys").paginate(UserName=user.user_name)
                for key in page["AccessKeyMetadata"]
            ]
        except (BotoCoreError, ClientError) as e:
            getLogger().warning(f"unable to list access keys: {e}")
            return []

    def get_access_key_last_used(self, access_key: AccessKey) -> Any:
        try:
            last_used = self._iam.get_access_key_last_used(AccessKeyId=access_key.id)["AccessKeyLastUsed"]
            if "LastUsedDate" in last_used:
                return last_used["LastUsedDate"]

        except (BotoCoreError, ClientError) as e:
            key_id = access_key.id
            getLogger().warning(f"unable to get access key last used for key: {key_id}: {e}")

        return None
