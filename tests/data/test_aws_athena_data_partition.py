from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, patch

from datetime import date

from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.data.aws_scanner_exceptions import InvalidDataPartitionException


@patch("src.data.aws_athena_data_partition.AwsAthenaDataPartition._today")
class TestAwsAthenaDataPartitionWithMockToday(AwsScannerTestCase):
    def test_data_partition_in_range(self, mock_today: Mock) -> None:
        mock_today.return_value = date(2021, 3, 10)
        self.assertEqual("AwsAthenaDataPartition(year='2021', month='03')", str(AwsAthenaDataPartition(2021, 3)))
        self.assertEqual("AwsAthenaDataPartition(year='2020', month='12')", str(AwsAthenaDataPartition(2020, 12)))

    def test_data_partition_out_of_range(self, mock_today: Mock) -> None:
        mock_today.return_value = date(2020, 10, 16)
        expected_msg = (
            r"invalid partition \(2020, 6\). "
            r"Should be one of {\(2020, 7\), \(2020, 8\), \(2020, 9\), \(2020, 10\)}. "
            "Retention 90 days."
        )
        with self.assertRaisesRegex(InvalidDataPartitionException, expected_msg):
            AwsAthenaDataPartition(2020, 6)


class TestAwsAthenaDataPartition(AwsScannerTestCase):
    def test_today(self) -> None:
        self.assertEqual(date.today(), AwsAthenaDataPartition(date.today().year, date.today().month)._today())
