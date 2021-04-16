from dataclasses import dataclass
from datetime import date, timedelta
from typing import Iterable, Tuple

from src.aws_scanner_config import AwsScannerConfig as Config
from src.data.aws_scanner_exceptions import InvalidDataPartitionException


@dataclass
class AwsAthenaDataPartition:
    year: str
    month: str

    def __init__(self, year: int, month: int):
        self._validate(year, month, Config().cloudtrail_log_retention_days())
        self.year = str(year)
        self.month = "%02d" % month

    def _validate(self, year: int, month: int, retention: int) -> None:
        partitions = self._get_valid_partitions(retention)
        if (year, month) not in partitions:
            raise InvalidDataPartitionException(year, month, partitions, retention)

    def _get_valid_partitions(self, retention: int) -> Iterable[Tuple[int, int]]:
        return {(d.year, d.month) for d in [self._today() - timedelta(delta) for delta in range(retention)]}

    @staticmethod
    def _today() -> date:
        return date.today()
