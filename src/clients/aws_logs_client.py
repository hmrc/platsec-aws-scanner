from logging import getLogger

from botocore.client import BaseClient


class AwsLogsClient:
    def __init__(self, boto_logs: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._logs = boto_logs
