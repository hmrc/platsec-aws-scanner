from logging import getLogger

from botocore.client import BaseClient


class AwsIamClient:
    def __init__(self, boto_iam: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._iam = boto_iam
