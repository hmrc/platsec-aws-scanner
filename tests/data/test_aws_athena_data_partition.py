from unittest import TestCase

from datetime import date

from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.data.aws_scanner_exceptions import InvalidDataPartitionException, InvalidRegionException


class TestAwsAthenaDataPartition(TestCase):
    def test_data_partition_with_year_month_in_range(self) -> None:
        partition_september = AwsAthenaDataPartition("eu", 2020, 9)
        self.assertEqual("2020", partition_september.year)
        self.assertEqual("09", partition_september.month)
        self.assertEqual("eu", partition_september.region)

        partition_october = AwsAthenaDataPartition("us", 2020, 10)
        self.assertEqual("2020", partition_october.year)
        self.assertEqual("10", partition_october.month)
        self.assertEqual("us", partition_october.region)

    def test_data_partition_with_year_month_out_of_range(self) -> None:
        expected_msg = (
            r"invalid partition \(2020, 6\). "
            r"Should be one of \[\(2020, 11\), \(2020, 10\), \(2020, 9\), \(2020, 8\)\]. "
            "Retention 90 days."
        )
        with self.assertRaisesRegex(InvalidDataPartitionException, expected_msg):
            AwsAthenaDataPartition("eu", 2020, 6)

    def test_data_partition_with_year_month_day_in_range(self) -> None:
        partition_september = AwsAthenaDataPartition("eu", 2020, 9, 3)
        self.assertEqual("2020", partition_september.year)
        self.assertEqual("09", partition_september.month)
        self.assertEqual("03", partition_september.day)
        self.assertEqual("eu", partition_september.region)

        partition_september = AwsAthenaDataPartition("eu", 2020, 10, 24)
        self.assertEqual("2020", partition_september.year)
        self.assertEqual("10", partition_september.month)
        self.assertEqual("24", partition_september.day)
        self.assertEqual("eu", partition_september.region)

    def test_data_partition_with_year_month_day_out_of_range(self) -> None:
        expected_msg = r"invalid partition \(2020, 8, 1\)"
        with self.assertRaisesRegex(InvalidDataPartitionException, expected_msg):
            AwsAthenaDataPartition("eu", 2020, 8, 1)

    def test_today(self) -> None:
        self.assertEqual(date.today(), AwsAthenaDataPartition._today())

    def test_invalid_region(self) -> None:
        expected_msg = r"invalid region 'abc'. Should be one of \['us', 'eu'\]."
        with self.assertRaisesRegex(InvalidRegionException, expected_msg):
            AwsAthenaDataPartition("abc", 2020, 11)
