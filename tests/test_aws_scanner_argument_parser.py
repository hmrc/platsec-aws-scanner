from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import patch

from contextlib import redirect_stderr
from io import StringIO

from src.aws_scanner_argument_parser import AwsScannerArgumentParser


class TestAwsScannerArgumentParser(AwsScannerTestCase):
    def test_parse_args_for_service_usage_task(self) -> None:
        with patch("sys.argv", "prog service_usage -u bob -t 666666 -y 2021 -m 02 -s ssm -v info".split()):
            short_args = AwsScannerArgumentParser().parse_args()

        with patch(
            "sys.argv",
            "prog service_usage --username bob --token 666666 --year 2021 --month 02 --service ssm".split(),
        ):
            long_args = AwsScannerArgumentParser().parse_args()

        for args in [short_args, long_args]:
            self.assertEqual(args.task, "service_usage")
            self.assertEqual(args.username, "bob")
            self.assertEqual(args.mfa_token, "666666")
            self.assertEqual(args.year, 2021)
            self.assertEqual(args.month, 2)
            self.assertEqual(args.accounts, None)
            self.assertEqual(args.service, "ssm")

    def test_parse_args_for_role_usage_task(self) -> None:
        with patch("sys.argv", "prog role_usage -u tom -t 654321 -y 2018 -m 1 -r RoleVerySensitive -v info".split()):
            short_args = AwsScannerArgumentParser().parse_args()

        with patch(
            "sys.argv",
            "prog role_usage --username tom --token 654321 --year 2018 --month 1 --role RoleVerySensitive".split(),
        ):
            long_args = AwsScannerArgumentParser().parse_args()

        for args in [short_args, long_args]:
            self.assertEqual(args.task, "role_usage")
            self.assertEqual(args.username, "tom")
            self.assertEqual(args.mfa_token, "654321")
            self.assertEqual(args.year, 2018)
            self.assertEqual(args.month, 1)
            self.assertEqual(args.accounts, None)
            self.assertEqual(args.role, "RoleVerySensitive")

    def test_parse_args_for_principal_task(self) -> None:
        with patch("sys.argv", "prog find_principal -u tom -t 987654 -y 2020 -m 11 -i 127.0.0.1 -v info".split()):
            short_args = AwsScannerArgumentParser().parse_args()

        with patch(
            "sys.argv",
            "prog find_principal --username tom --token 987654 --year 2020 --month 11 --ip 127.0.0.1".split(),
        ):
            long_args = AwsScannerArgumentParser().parse_args()

        for args in [short_args, long_args]:
            self.assertEqual(args.task, "find_principal")
            self.assertEqual(args.username, "tom")
            self.assertEqual(args.mfa_token, "987654")
            self.assertEqual(args.year, 2020)
            self.assertEqual(args.month, 11)
            self.assertEqual(args.accounts, None)
            self.assertEqual(args.source_ip, "127.0.0.1")

    def test_parse_args_for_create_table_task(self) -> None:
        with patch("sys.argv", "prog create_table -u john -t 444555 -y 2019 -m 5 -a 1,2,3 -v info".split()):
            short_args = AwsScannerArgumentParser().parse_args()

        with patch(
            "sys.argv",
            "prog create_table --username john --token 444555 --year 2019 --month 5 --accounts 1,2,3".split(),
        ):
            long_args = AwsScannerArgumentParser().parse_args()

        for args in [short_args, long_args]:
            self.assertEqual(args.task, "create_table")
            self.assertEqual(args.username, "john")
            self.assertEqual(args.mfa_token, "444555")
            self.assertEqual(args.year, 2019)
            self.assertEqual(args.month, 5)
            self.assertEqual(args.accounts, ["1", "2", "3"])

    def test_parse_args_for_list_accounts_task(self) -> None:
        with patch("sys.argv", "prog list_accounts -u rob -t 446655 -v debug".split()):
            short_args = AwsScannerArgumentParser().parse_args()

        with patch("sys.argv", "prog list_accounts --username rob --token 446655 --verbosity debug".split()):
            long_args = AwsScannerArgumentParser().parse_args()

        for args in [short_args, long_args]:
            self.assertEqual(args.task, "list_accounts")
            self.assertEqual(args.username, "rob")
            self.assertEqual(args.mfa_token, "446655")
            self.assertEqual(args.log_level, "debug")

    def test_parse_args_for_list_ssm_parameters_task(self) -> None:
        with patch("sys.argv", "prog list_ssm_parameters -u kev -t 446465 -v warning".split()):
            short_args = AwsScannerArgumentParser().parse_args()

        with patch("sys.argv", "prog list_ssm_parameters --username kev --token 446465 --verbosity warning".split()):
            long_args = AwsScannerArgumentParser().parse_args()

        for args in [short_args, long_args]:
            self.assertEqual(args.task, "list_ssm_parameters")
            self.assertEqual(args.username, "kev")
            self.assertEqual(args.mfa_token, "446465")
            self.assertEqual(args.log_level, "warning")

    def test_parse_args_for_drop_task(self) -> None:
        with patch("sys.argv", "prog drop -t 433516 -v info".split()):
            short_args = AwsScannerArgumentParser().parse_args()

        with patch("sys.argv", "prog drop --token 433516 --verbosity info".split()):
            long_args = AwsScannerArgumentParser().parse_args()

        for args in [short_args, long_args]:
            self.assertEqual(args.task, "drop")
            self.assertEqual(args.username, "joe.bloggs")
            self.assertEqual(args.mfa_token, "433516")
            self.assertEqual(args.log_level, "info")

    def test_parse_args_for_audit_s3_task(self) -> None:
        with patch("sys.argv", "prog audit_s3 -t 446468 -a 1,2 -v error".split()):
            short_args = AwsScannerArgumentParser().parse_args()

        with patch("sys.argv", "prog audit_s3 --token 446468 --accounts 1,2 --verbosity error".split()):
            long_args = AwsScannerArgumentParser().parse_args()

        for args in [short_args, long_args]:
            self.assertEqual(args.task, "audit_s3")
            self.assertEqual(args.username, "joe.bloggs")
            self.assertEqual(args.mfa_token, "446468")
            self.assertEqual(args.accounts, ["1", "2"])
            self.assertEqual(args.log_level, "error")

    def test_task_is_mandatory(self) -> None:
        with redirect_stderr(StringIO()) as err:
            with self.assertRaises(SystemExit):
                with patch("sys.argv", "prog".split()):
                    AwsScannerArgumentParser().parse_args()
        self.assertIn("required: task", err.getvalue())
