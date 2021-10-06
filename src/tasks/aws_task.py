from typing import Any, Dict
from logging import getLogger

from src.data.aws_task_report import AwsTaskReport
from src.data.aws_organizations_types import Account


class AwsTask:
    def __init__(self, description: str, account: Account):
        self._logger = getLogger(self.__class__.__name__)
        self._description = description
        self._account = account

    def run(self, client: Any) -> AwsTaskReport:
        self._logger.info(f"running {self}")
        return AwsTaskReport(
            account=self._account, description=self._description, partition=None, results=self._run_task(client)
        )

    @property
    def account(self) -> Account:
        return self._account

    def _run_task(self, client: Any) -> Dict[Any, Any]:
        raise NotImplementedError("this is an abstract class")

    def __str__(self) -> str:
        return f"task '{self._description}' for '{self._account}'"
