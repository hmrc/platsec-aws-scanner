from logging import getLogger

from botocore.client import BaseClient


class AwsEC2Client:
    def __init__(self, boto_ec2: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._ec2 = boto_ec2
