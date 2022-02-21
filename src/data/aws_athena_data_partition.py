from dataclasses import dataclass
from datetime import date, timedelta
from typing import Iterable, Optional, Tuple

from boto3.session import Session

from src.aws_scanner_config import AwsScannerConfig as Config
from src.data.aws_scanner_exceptions import InvalidDataPartitionException, InvalidRegionException


@dataclass
class AwsAthenaDataPartition:
    year: str
    month: str
    region: str
    day: Optional[str]

    def __init__(self, region: str, year: int, month: int, day: Optional[int] = None):
        self.year, self.month, self.day = self._validate_date(year, month, day)
        self.region = self._validate_region(region)

    def _validate_date(self, year: int, month: int, day: Optional[int]) -> Tuple[str, str, Optional[str]]:
        retention = Config().cloudtrail_logs_retention_days()
        partitions = self._get_valid_year_month_day(retention) if day else self._get_valid_year_month(retention)

        if tuple(val for val in (year, month, day) if val) not in partitions:
            raise InvalidDataPartitionException(partitions, retention, year, month, day)

        return str(year), "%02d" % month, "%02d" % day if day else None

    @staticmethod
    def _validate_region(region: str) -> str:
        regions = Session().get_available_regions("athena")

        if region not in regions:
            raise InvalidRegionException(region, regions)

        return region

    def _get_valid_year_month(self, retention: int) -> Iterable[Tuple[int, int]]:
        return {(d.year, d.month) for d in self._get_valid_dates(retention)}

    def _get_valid_year_month_day(self, retention: int) -> Iterable[Tuple[int, int, int]]:
        return {(d.year, d.month, d.day) for d in self._get_valid_dates(retention)}

    def _get_valid_dates(self, retention: int) -> Iterable[date]:
        return [self._today() - timedelta(delta) for delta in range(retention)]

    @staticmethod
    def _today() -> date:
        return date.today()
