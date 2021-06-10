from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import patch

from contextlib import redirect_stderr
from io import StringIO

from src.aws_scanner_argument_parser import AwsScannerArgumentParser
from src.data import SERVICE_ACCOUNT_TOKEN, SERVICE_ACCOUNT_USER


class TestAwsScannerArgumentParser(AwsScannerTestCase):
    def test_parse_cli_args_for_service_usage_task(self) -> None:
        with patch("sys.argv", ". service_usage -u bob -t 666666 -y 2020 -m 9 -re eu -s ssm -v info".split()):
            short_args = AwsScannerArgumentParser().parse_cli_args()

        with patch(
            "sys.argv",
            ". service_usage --username bob --token 666666 --year 2020 --month 09 --region eu --service ssm".split(),
        ):
            long_args = AwsScannerArgumentParser().parse_cli_args()

        for args in [short_args, long_args]:
            self.assertEqual(args.task, "service_usage")
            self.assertEqual(args.username, "bob")
            self.assertEqual(args.mfa_token, "666666")
            self.assertEqual(args.partition.year, "2020")
            self.assertEqual(args.partition.month, "09")
            self.assertEqual(args.partition.region, "eu")
            self.assertEqual(args.accounts, None)
            self.assertEqual(args.service, "ssm")

    def test_parse_cli_args_for_role_usage_task(self) -> None:
        with patch("sys.argv", ". role_usage -u tom -t 654321 -y 2020 -m 10 -r TheRole -re us -v info".split()):
            short_args = AwsScannerArgumentParser().parse_cli_args()

        with patch(
            "sys.argv",
            ". role_usage --username tom --token 654321 --year 2020 --month 10 --role TheRole --region us".split(),
        ):
            long_args = AwsScannerArgumentParser().parse_cli_args()

        for args in [short_args, long_args]:
            self.assertEqual(args.task, "role_usage")
            self.assertEqual(args.username, "tom")
            self.assertEqual(args.mfa_token, "654321")
            self.assertEqual(args.partition.year, "2020")
            self.assertEqual(args.partition.month, "10")
            self.assertEqual(args.partition.region, "us")
            self.assertEqual(args.accounts, None)
            self.assertEqual(args.role, "TheRole")

    def test_parse_cli_args_for_principal_task(self) -> None:
        with patch("sys.argv", ". find_principal -u tom -t 987654 -y 2020 -m 11 -i 127.0.0.1 -re eu -v info".split()):
            short_args = AwsScannerArgumentParser().parse_cli_args()

        with patch(
            "sys.argv",
            ". find_principal --username tom --token 987654 --year 2020 --month 11 --ip 127.0.0.1 --region eu".split(),
        ):
            long_args = AwsScannerArgumentParser().parse_cli_args()

        for args in [short_args, long_args]:
            self.assertEqual(args.task, "find_principal")
            self.assertEqual(args.username, "tom")
            self.assertEqual(args.mfa_token, "987654")
            self.assertEqual(args.partition.year, "2020")
            self.assertEqual(args.partition.month, "11")
            self.assertEqual(args.partition.region, "eu")
            self.assertEqual(args.accounts, None)
            self.assertEqual(args.source_ip, "127.0.0.1")

    def test_parse_cli_args_for_create_table_task(self) -> None:
        with patch("sys.argv", ". create_table -u john -t 444555 -y 2020 -m 8 -a 1,2,3 -v info".split()):
            short_args = AwsScannerArgumentParser().parse_cli_args()

        with patch(
            "sys.argv",
            ". create_table --username john --token 444555 --year 2020 --month 8 --accounts 1,2,3".split(),
        ):
            long_args = AwsScannerArgumentParser().parse_cli_args()

        for args in [short_args, long_args]:
            self.assertEqual(args.task, "create_table")
            self.assertEqual(args.username, "john")
            self.assertEqual(args.mfa_token, "444555")
            self.assertEqual(args.partition.year, "2020")
            self.assertEqual(args.partition.month, "08")
            self.assertEqual(args.partition.region, "eu")
            self.assertEqual(args.accounts, ["1", "2", "3"])

    def test_parse_cli_args_for_list_accounts_task(self) -> None:
        with patch("sys.argv", ". list_accounts -u rob -t 446655 -v debug".split()):
            short_args = AwsScannerArgumentParser().parse_cli_args()

        with patch("sys.argv", ". list_accounts --username rob --token 446655 --verbosity debug".split()):
            long_args = AwsScannerArgumentParser().parse_cli_args()

        for args in [short_args, long_args]:
            self.assertEqual(args.task, "list_accounts")
            self.assertEqual(args.username, "rob")
            self.assertEqual(args.mfa_token, "446655")
            self.assertEqual(args.log_level, "DEBUG")

    def test_parse_cli_args_for_list_ssm_parameters_task(self) -> None:
        with patch("sys.argv", ". list_ssm_parameters -u kev -t 446465 -v warning".split()):
            short_args = AwsScannerArgumentParser().parse_cli_args()

        with patch("sys.argv", ". list_ssm_parameters --username kev --token 446465 --verbosity warning".split()):
            long_args = AwsScannerArgumentParser().parse_cli_args()

        for args in [short_args, long_args]:
            self.assertEqual(args.task, "list_ssm_parameters")
            self.assertEqual(args.username, "kev")
            self.assertEqual(args.mfa_token, "446465")
            self.assertEqual(args.log_level, "WARNING")

    def test_parse_cli_args_for_drop_task(self) -> None:
        with patch("sys.argv", ". drop -t 433516 -v info".split()):
            short_args = AwsScannerArgumentParser().parse_cli_args()

        with patch("sys.argv", ". drop --token 433516 --verbosity info".split()):
            long_args = AwsScannerArgumentParser().parse_cli_args()

        for args in [short_args, long_args]:
            self.assertEqual(args.task, "drop")
            self.assertEqual(args.username, "joe.bloggs")
            self.assertEqual(args.mfa_token, "433516")
            self.assertEqual(args.log_level, "INFO")

    def test_parse_cli_args_for_audit_s3_task(self) -> None:
        with patch("sys.argv", ". audit_s3 -t 446468 -a 1,2 -v error".split()):
            short_args = AwsScannerArgumentParser().parse_cli_args()

        with patch("sys.argv", ". audit_s3 --token 446468 --accounts 1,2 --verbosity error".split()):
            long_args = AwsScannerArgumentParser().parse_cli_args()

        for args in [short_args, long_args]:
            self.assertEqual(args.task, "audit_s3")
            self.assertEqual(args.username, "joe.bloggs")
            self.assertEqual(args.mfa_token, "446468")
            self.assertEqual(args.accounts, ["1", "2"])
            self.assertEqual(args.log_level, "ERROR")

    def test_cli_task_is_mandatory(self) -> None:
        with redirect_stderr(StringIO()) as err:
            with self.assertRaises(SystemExit):
                with patch("sys.argv", ".".split()):
                    AwsScannerArgumentParser().parse_cli_args()
        self.assertIn("required: task", err.getvalue())

    def test_lambda_task_is_mandatory(self) -> None:
        with redirect_stderr(StringIO()) as err:
            with self.assertRaises(SystemExit):
                AwsScannerArgumentParser().parse_lambda_args({})
        self.assertIn("error: argument task", err.getvalue())

    def test_parse_lambda_args_for_service_usage_task(self) -> None:
        lambda_args = AwsScannerArgumentParser().parse_lambda_args(
            {"year": 2020, "month": 8, "task": "service_usage", "service": "ssm", "username": "something", "token": "1"}
        )

        self.assertEqual(lambda_args.task, "service_usage")
        self.assertEqual(lambda_args.username, SERVICE_ACCOUNT_USER)
        self.assertEqual(lambda_args.mfa_token, SERVICE_ACCOUNT_TOKEN)
        self.assertEqual(lambda_args.partition.year, "2020")
        self.assertEqual(lambda_args.partition.month, "08")
        self.assertEqual(lambda_args.partition.region, "eu")
        self.assertEqual(lambda_args.accounts, None)
        self.assertEqual(lambda_args.service, "ssm")
