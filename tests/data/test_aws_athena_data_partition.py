from unittest import TestCase

from datetime import date

from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.data.aws_scanner_exceptions import InvalidDataPartitionException, InvalidRegionException


class TestAwsAthenaDataPartition(TestCase):
    def test_data_partition_in_range(self) -> None:
        self.assertEqual(
            "AwsAthenaDataPartition(year='2020', month='09', region='eu')",
            str(AwsAthenaDataPartition(2020, 9, "eu")),
        )
        self.assertEqual(
            "AwsAthenaDataPartition(year='2020', month='10', region='us')",
            str(AwsAthenaDataPartition(2020, 10, "us")),
        )

    def test_data_partition_out_of_range(self) -> None:
        expected_msg = (
            r"invalid partition \(2020, 6\). "
            r"Should be one of {\(2020, 8\), \(2020, 9\), \(2020, 10\), \(2020, 11\)}. "
            "Retention 90 days."
        )
        with self.assertRaisesRegex(InvalidDataPartitionException, expected_msg):
            AwsAthenaDataPartition(2020, 6, "eu")

    def test_today(self) -> None:
        self.assertEqual(date.today(), AwsAthenaDataPartition._today())

    def test_invalid_region(self) -> None:
        expected_msg = r"invalid region 'abc'. Should be one of \['us', 'eu'\]."
        with self.assertRaisesRegex(InvalidRegionException, expected_msg):
            AwsAthenaDataPartition(2020, 11, "abc")
