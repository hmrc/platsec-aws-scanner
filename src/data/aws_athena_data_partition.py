from dataclasses import dataclass
from datetime import date, timedelta
from typing import Iterable, Tuple

from boto3.session import Session

from src.aws_scanner_config import AwsScannerConfig as Config
from src.data.aws_scanner_exceptions import InvalidDataPartitionException, InvalidRegionException


@dataclass
class AwsAthenaDataPartition:
    year: str
    month: str
    region: str

    def __init__(self, year: int, month: int, region: str):
        self.year, self.month = self._validate_date(year, month)
        self.region = self._validate_region(region)

    def _validate_date(self, year: int, month: int) -> Tuple[str, str]:
        retention = Config().cloudtrail_logs_retention_days()
        partitions = self._get_valid_partitions(retention)

        if (year, month) not in partitions:
            raise InvalidDataPartitionException(year, month, partitions, retention)

        return str(year), "%02d" % month

    @staticmethod
    def _validate_region(region: str) -> str:
        regions = Session().get_available_regions("athena")

        if region not in regions:
            raise InvalidRegionException(region, regions)

        return region

    def _get_valid_partitions(self, retention: int) -> Iterable[Tuple[int, int]]:
        return {(d.year, d.month) for d in [self._today() - timedelta(delta) for delta in range(retention)]}

    @staticmethod
    def _today() -> date:
        return date.today()
