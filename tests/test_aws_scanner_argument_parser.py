from unittest.mock import patch
import pytest
from typing import Any

from src.aws_scanner_argument_parser import AwsScannerArgumentParser
from src.data import SERVICE_ACCOUNT_TOKEN, SERVICE_ACCOUNT_USER


def test_parse_cli_args_for_cost_usage_task() -> None:
    with patch("sys.argv", ". cost_explorer -u bob -a 3,2,1 -t 666666".split()):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch(
        "sys.argv",
        ". cost_explorer --username bob --account 3,2,1 --token 666666".split(),
    ):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "cost_explorer"
        assert args.username == "bob"
        assert args.mfa_token == "666666"
        assert args.accounts == ["3", "2", "1"]


def test_parse_cli_args_for_service_usage_task() -> None:
    with patch(
        "sys.argv", ". service_usage -u bob -t 666666 -y 2020 -m 9 -apr eu -re eu-west-2 -s ssm,s3 -v info".split()
    ):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch(
        "sys.argv",
        ". service_usage --username bob --token 666666 --year 2020 --month 9 \
        --athena_partition_region eu --region eu-west-2 --services ssm,s3".split(),
    ):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "service_usage"
        assert args.username == "bob"
        assert args.mfa_token == "666666"
        assert args.partition.year == "2020"
        assert args.partition.month == "09"
        assert args.partition.region == "eu"
        assert args.region == "eu-west-2"
        assert args.accounts is None
        assert args.services == ["ssm", "s3"]


def test_parse_cli_args_for_role_usage_task() -> None:
    with patch("sys.argv", ". role_usage -u tom -t 654321 -y 2020 -m 10 -r TheRole -apr us -v info".split()):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch(
        "sys.argv",
        ". role_usage --username tom --token 654321 --year 2020 --month 10 --role TheRole \
        --athena_partition_region us".split(),
    ):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "role_usage"
        assert args.username == "tom"
        assert args.mfa_token == "654321"
        assert args.partition.year == "2020"
        assert args.partition.month == "10"
        assert args.partition.region == "us"
        assert args.accounts is None
        assert args.role == "TheRole"


def test_parse_cli_args_for_principal_task() -> None:
    with patch("sys.argv", ". find_principal -u tom -t 987654 -y 2020 -m 11 -i 127.0.0.1 -apr eu -v info".split()):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch(
        "sys.argv",
        ". find_principal --username tom --token 987654 --year 2020 --month 11 --ip 127.0.0.1 --region eu".split(),
    ):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "find_principal"
        assert args.username == "tom"
        assert args.mfa_token == "987654"
        assert args.partition.year == "2020"
        assert args.partition.month == "11"
        assert args.partition.region == "eu"
        assert args.accounts is None
        assert args.source_ip == "127.0.0.1"


def test_parse_cli_args_for_create_table_task() -> None:
    with patch("sys.argv", ". create_table -u john -t 444555 -y 2020 -m 8 -a 1,2,3 -v info".split()):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch(
        "sys.argv",
        ". create_table --username john --token 444555 --year 2020 --month 8 --accounts 1,2,3".split(),
    ):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "create_table"
        assert args.username == "john"
        assert args.mfa_token == "444555"
        assert args.partition.year == "2020"
        assert args.partition.month == "08"
        assert args.partition.region == "eu"
        assert args.accounts == ["1", "2", "3"]


def test_parse_cli_args_for_list_accounts_task() -> None:
    with patch("sys.argv", ". list_accounts -u rob -t 446655 -v debug".split()):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch("sys.argv", ". list_accounts --username rob --token 446655 --verbosity debug".split()):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "list_accounts"
        assert args.username == "rob"
        assert args.mfa_token == "446655"
        assert args.log_level == "DEBUG"


def test_parse_cli_args_for_list_ssm_parameters_task() -> None:
    with patch("sys.argv", ". list_ssm_parameters -u kev -t 446465 -v warning".split()):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch("sys.argv", ". list_ssm_parameters --username kev --token 446465 --verbosity warning".split()):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "list_ssm_parameters"
        assert args.username == "kev"
        assert args.mfa_token == "446465"
        assert args.log_level == "WARNING"


def test_parse_cli_args_for_drop_task() -> None:
    with patch("sys.argv", ". drop -t 433516 -v info".split()):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch("sys.argv", ". drop --token 433516 --verbosity info".split()):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "drop"
        assert args.username == "joe.bloggs"
        assert args.mfa_token == "433516"
        assert args.log_level == "INFO"


def test_parse_cli_args_for_audit_s3_task() -> None:
    with patch("sys.argv", ". audit_s3 -t 446468 -a 1,2 -p prod -v error".split()):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch("sys.argv", ". audit_s3 --token 446468 --accounts 1,2 --parent prod --verbosity error".split()):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "audit_s3"
        assert args.username == "joe.bloggs"
        assert args.mfa_token == "446468"
        assert args.accounts == ["1", "2"]
        assert args.log_level == "ERROR"
        assert args.disable_account_lookup is False
        assert args.parent == "prod"


def test_parse_cli_args_for_audit_vpc_flow_logs_task() -> None:
    with patch("sys.argv", ". audit_vpc_flow_logs -t 223344 -a 5,9 -di true -e true -v debug".split()):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch(
        "sys.argv",
        ". audit_vpc_flow_logs --token 223344 --accounts 5,9 --disable_account_lookup 1 --enforce True".split(),
    ):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "audit_vpc_flow_logs"
        assert args.username == "joe.bloggs"
        assert args.mfa_token == "223344"
        assert args.accounts == ["5", "9"]
        assert args.enforce is True
        assert args.disable_account_lookup is True
        assert args.with_subscription_filter is False
        assert args.parent == "Parent OU"


def test_parse_cli_args_for_audit_vpc_dns_logs_task() -> None:
    with patch("sys.argv", ". audit_vpc_dns_logs -t 223344 -a 5,9 -di true -e true -v debug".split()):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch(
        "sys.argv",
        ". audit_vpc_dns_logs --token 223344 --accounts 5,9 --disable_account_lookup 1 --enforce True".split(),
    ):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "audit_vpc_dns_logs"
        assert args.username == "joe.bloggs"
        assert args.mfa_token == "223344"
        assert args.accounts == ["5", "9"]
        assert args.enforce is True
        assert args.disable_account_lookup is True
        assert args.with_subscription_filter is False
        assert args.parent == "Parent OU"


def test_parse_cli_args_for_enforce_false() -> None:
    with patch("sys.argv", ". audit_vpc_flow_logs --token 223344 --accounts 5,9 --enforce False".split()):
        long_args = AwsScannerArgumentParser().parse_cli_args()

        assert long_args.enforce is False


def test_parse_cli_args_with_subscription_filter() -> None:
    with patch("sys.argv", ". audit_vpc_flow_logs --token 223344 --with_subscription_filter true".split()):
        long_args = AwsScannerArgumentParser().parse_cli_args()
        assert long_args.with_subscription_filter is True

    with patch("sys.argv", ". audit_vpc_flow_logs --token 223344 --with_subscription_filter false".split()):
        long_args = AwsScannerArgumentParser().parse_cli_args()
        assert long_args.with_subscription_filter is False

    with patch("sys.argv", ". audit_vpc_flow_logs -t 223344 -w 1".split()):
        long_args = AwsScannerArgumentParser().parse_cli_args()
        assert long_args.with_subscription_filter is False


def test_parse_cli_args_for_audit_password_policy_task() -> None:
    with patch("sys.argv", ". audit_password_policy -t 797879 -a 7,8 -e true".split()):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch("sys.argv", ". audit_password_policy --token 797879 --accounts 7,8 --enforce True".split()):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "audit_password_policy"
        assert args.username == "joe.bloggs"
        assert args.mfa_token == "797879"
        assert args.accounts == ["7", "8"]
        assert args.enforce is True


def test_parse_cli_args_for_audit_cloudtrail_task() -> None:
    with patch("sys.argv", ". audit_cloudtrail -t 446655 -a 42".split()):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch("sys.argv", ". audit_cloudtrail --token 446655 --accounts 42".split()):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "audit_cloudtrail"
        assert args.username == "joe.bloggs"
        assert args.mfa_token == "446655"
        assert args.accounts == ["42"]


def test_parse_cli_args_for_audit_central_logging_task() -> None:
    with patch("sys.argv", ". audit_central_logging -t 787878".split()):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch("sys.argv", ". audit_central_logging --token 787878".split()):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "audit_central_logging"
        assert args.username == "joe.bloggs"
        assert args.mfa_token == "787878"


def test_parse_cli_args_for_create_flow_logs_table_year_month_day_task() -> None:
    with patch("sys.argv", ". create_flow_logs_table -y 2020 -m 9 -d 8 -t 466455".split()):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch("sys.argv", ". create_flow_logs_table --year 2020 --month 9 --day 8 --token 466455".split()):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "create_flow_logs_table"
        assert args.username == "joe.bloggs"
        assert args.mfa_token == "466455"
        assert args.partition.year == "2020"
        assert args.partition.month == "09"
        assert args.partition.day == "08"


def test_parse_cli_args_for_create_flow_logs_table_year_month_task() -> None:
    with patch("sys.argv", ". create_flow_logs_table -y 2020 -m 10 -t 788998".split()):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch("sys.argv", ". create_flow_logs_table --year 2020 --month 10 --token 788998".split()):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "create_flow_logs_table"
        assert args.username == "joe.bloggs"
        assert args.mfa_token == "788998"
        assert args.partition.year == "2020"
        assert args.partition.month == "10"
        assert args.partition.day is None


def test_parse_cli_args_for_create_flow_logs_table_with_unspecified_partition_task() -> None:
    with patch("sys.argv", ". create_flow_logs_table -t 464546".split()):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch("sys.argv", ". create_flow_logs_table --token 464546".split()):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "create_flow_logs_table"
        assert args.username == "joe.bloggs"
        assert args.mfa_token == "464546"
        assert args.partition.year == "2020"
        assert args.partition.month == "11"
        assert args.partition.day is None


def test_parse_cli_args_for_audit_vpc_peering() -> None:
    with patch("sys.argv", ". audit_vpc_peering -a 8,9 -t 799788".split()):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch("sys.argv", ". audit_vpc_peering --accounts 8,9 --token 799788".split()):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "audit_vpc_peering"
        assert args.accounts == ["8", "9"]
        assert args.username == "joe.bloggs"
        assert args.mfa_token == "799788"


def test_parse_cli_args_for_audit_ec2_instances() -> None:
    with patch("sys.argv", ". audit_ec2_instances -a 15,43 -t 465132".split()):
        short_args = AwsScannerArgumentParser().parse_cli_args()

    with patch("sys.argv", ". audit_ec2_instances --accounts 15,43 --token 465132".split()):
        long_args = AwsScannerArgumentParser().parse_cli_args()

    for args in [short_args, long_args]:
        assert args.task == "audit_ec2_instances"
        assert args.accounts == ["15", "43"]
        assert args.username == "joe.bloggs"
        assert args.mfa_token == "465132"


def test_default_log_level_is_warning() -> None:
    with patch("sys.argv", ". audit_vpc_flow_logs --token 223344".split()):
        args = AwsScannerArgumentParser().parse_cli_args()

        assert args.log_level == "WARNING"


def test_invalid_log_level_logs_and_exits(capsys: Any) -> None:
    with patch("sys.argv", ". audit_vpc_flow_logs --token 223344 -v banana".split()):
        with pytest.raises(SystemExit):
            AwsScannerArgumentParser().parse_cli_args()
    error_logs = capsys.readouterr().err
    assert "banana" in error_logs
    assert "verbosity" in error_logs


def test_cli_task_is_mandatory(capsys: Any) -> None:
    with patch("sys.argv", ".".split()):
        with pytest.raises(SystemExit):
            AwsScannerArgumentParser().parse_cli_args()
    assert "required: task" in capsys.readouterr().err


def test_lambda_task_is_mandatory(capsys: Any) -> None:
    with pytest.raises(SystemExit):
        AwsScannerArgumentParser().parse_lambda_args({})
    assert "error: argument task" in capsys.readouterr().err


def test_parse_lambda_args_for_service_usage_task() -> None:
    lambda_args = AwsScannerArgumentParser().parse_lambda_args(
        {
            "year": 2020,
            "month": 8,
            "task": "service_usage",
            "services": "ssm",
            "username": "something",
            "token": "1",
            "disable_account_lookup": 1,
        }
    )
    assert lambda_args.task == "service_usage"
    assert lambda_args.username == SERVICE_ACCOUNT_USER
    assert lambda_args.mfa_token == SERVICE_ACCOUNT_TOKEN
    assert lambda_args.partition.year == "2020"
    assert lambda_args.partition.month == "08"
    assert lambda_args.partition.region == "eu"
    assert lambda_args.accounts is None
    assert lambda_args.services == ["ssm"]
    assert lambda_args.disable_account_lookup is True
