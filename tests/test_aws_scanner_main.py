# type: ignore
from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, patch

from contextlib import redirect_stdout
from io import StringIO

from src.clients.aws_client_factory import AwsCredentials
from src.aws_scanner_main import AwsScannerMain
from src.data.aws_scanner_exceptions import AwsScannerException
from src.json_serializer import to_json

from tests.test_types_generator import task_report

CLIENT_FACTORY_REF = "src.clients.aws_client_factory.AwsClientFactory"
SCANNER_REF = "src.aws_scanner.AwsScanner"

credentials = AwsCredentials("some_access_key_id", "some_secret_access_key", "some_session_token")


def get_session_token(mfa, username):
    if mfa != "123456" or username != "bob":
        raise AssertionError(f"mfa: got {mfa}, expected 123456 | username: got {username}, expected bob")
    return credentials


def init_scanner(task_builder, task_runner):
    if task_builder._orgs._mock_name != "the_orgs_client" or task_runner._client_factory._session_token != credentials:
        raise AssertionError("the aws_scanner.AwsScanner instance wasn't initialised with the expected clients")


def init_scanner_with_target_accounts(task_builder, task_runner):
    init_scanner(task_builder, task_runner)
    if task_builder._accounts != ["1", "2", "3"]:
        raise AssertionError("the aws_scanner.AwsScanner instance wasn't initialised with the expected target accounts")


def get_organizations_client():
    return Mock(name="the_orgs_client")


def get_athena_client():
    return Mock(name="the_athena_client")


def build_test_report(description):
    return [task_report(description=description, results={"key": "val"})]


@patch(f"{CLIENT_FACTORY_REF}._get_session_token", side_effect=get_session_token)
@patch(f"{CLIENT_FACTORY_REF}.get_organizations_client", side_effect=get_organizations_client)
@patch(f"{CLIENT_FACTORY_REF}.get_athena_client", side_effect=get_athena_client)
@patch(f"{SCANNER_REF}.__init__", side_effect=init_scanner)
class TestAwsScannerMain(AwsScannerTestCase):
    def test_main_with_service_usage_cmd(self, _, __, ___, ____):
        report = build_test_report("service_usage")
        with patch("sys.argv", "prog service_usage -u bob -t 123456 -y 2021 -m 2 -s ssm".split()):
            with patch(f"{SCANNER_REF}.scan_service_usage", return_value=report) as mock_scan_service_usage:
                with redirect_stdout(StringIO()) as out:
                    AwsScannerMain()
        mock_scan_service_usage.assert_called_once_with(2021, 2, "ssm")
        self.assertEqual(f"{to_json(report)}\n", out.getvalue())

    def test_main_with_role_usage_cmd(self, _, __, ___, ____):
        report = build_test_report("role_usage")
        with patch("sys.argv", "prog role_usage -u bob -t 123456 -y 2021 -m 2 -r SomeSensitiveRole".split()):
            with patch(f"{SCANNER_REF}.scan_role_usage", return_value=report) as mock_scan_role_usage:
                with redirect_stdout(StringIO()) as out:
                    AwsScannerMain()
        mock_scan_role_usage.assert_called_once_with(2021, 2, "SomeSensitiveRole")
        self.assertEqual(f"{to_json(report)}\n", out.getvalue())

    def test_main_with_find_principal_by_ip_cmd(self, _, __, ___, ____):
        report = build_test_report("principal")
        with patch("sys.argv", "prog find_principal -u bob -t 123456 -y 2022 -m 04 -i 127.0.0.5".split()):
            with patch(f"{SCANNER_REF}.find_principal_by_ip", return_value=report) as mock_find_principal_by_ip:
                with redirect_stdout(StringIO()) as out:
                    AwsScannerMain()
        mock_find_principal_by_ip.assert_called_once_with(2022, 4, "127.0.0.5")
        self.assertEqual(f"{to_json(report)}\n", out.getvalue())

    def test_main_with_create_table_cmd(self, _, __, ___, ____):
        report = build_test_report("create_table")
        with patch("sys.argv", "prog create_table -u bob -t 123456 -y 2020 -m 02 -a 1,2,3".split()):
            with patch(f"{SCANNER_REF}.__init__", side_effect=init_scanner_with_target_accounts):
                with patch(f"{SCANNER_REF}.create_table", return_value=report) as mock_create_table:
                    with redirect_stdout(StringIO()) as out:
                        AwsScannerMain()
        mock_create_table.assert_called_once_with(2020, 2)
        self.assertEqual(f"{to_json(report)}\n", out.getvalue())

    def test_main_with_list_accounts_cmd(self, _, __, ___, ____):
        report = build_test_report("list_accounts")
        with patch("sys.argv", "prog list_accounts -u bob -t 123456".split()):
            with patch(f"{SCANNER_REF}.list_accounts", return_value=report) as mock_clean:
                with redirect_stdout(StringIO()) as out:
                    AwsScannerMain()
        mock_clean.assert_called_once_with()
        self.assertEqual(f"{to_json(report)}\n", out.getvalue())

    def test_main_with_drop_cmd(self, _, __, ___, ____):
        report = build_test_report("drop")
        with patch("sys.argv", "prog drop -u bob -t 123456".split()):
            with patch(f"{SCANNER_REF}.clean_athena", return_value=report) as mock_clean:
                with redirect_stdout(StringIO()) as out:
                    AwsScannerMain()
        mock_clean.assert_called_once_with()
        self.assertEqual(f"{to_json(report)}\n", out.getvalue())

    def test_main_failure(self, _, __, ___, ____):
        with patch("sys.argv", "prog drop -u bob -t 123456".split()):
            with patch(f"{SCANNER_REF}.clean_athena", side_effect=AwsScannerException("got a problem")):
                with self.assertRaises(SystemExit) as se:
                    with self.assertLogs("AwsScannerMain", level="ERROR") as error_log:
                        AwsScannerMain()
        self.assertEqual(1, se.exception.code, f"exit code should be 1 but got {se.exception.code}")
        self.assertIn("AwsScannerException: got a problem", error_log.output[0])
