from argparse import ArgumentParser
from dataclasses import dataclass
from functools import reduce
from typing import Any, Dict, List, Optional

from src.aws_scanner_config import AwsScannerConfig as Config
from src.data import SERVICE_ACCOUNT_TOKEN, SERVICE_ACCOUNT_USER
from src.data.aws_athena_data_partition import AwsAthenaDataPartition


@dataclass
class AwsScannerArguments:
    username: str
    mfa_token: str
    task: str
    year: int
    month: int
    region: str
    accounts: Optional[List[str]]
    service: str
    role: str
    source_ip: str
    log_level: str
    enforce: bool

    @property
    def partition(self) -> AwsAthenaDataPartition:
        return AwsAthenaDataPartition(year=self.year, month=self.month, region=self.region)


class AwsScannerCommands:
    service_usage: str = "service_usage"
    role_usage: str = "role_usage"
    find_principal: str = "find_principal"
    create_table: str = "create_table"
    list_accounts: str = "list_accounts"
    list_ssm_parameters: str = "list_ssm_parameters"
    drop: str = "drop"
    audit_s3: str = "audit_s3"
    audit_vpc_flow_logs: str = "audit_vpc_flow_logs"
    cost_usage: str = "cost_usage"


class AwsScannerArgumentParser:
    @staticmethod
    def _add_auth_args(parser: ArgumentParser) -> None:
        parser.add_argument("-u", "--username", type=str, help="username that assumes AWS roles")
        parser.add_argument("-t", "--token", type=str, required=True, help="AWS mfa token")

    @staticmethod
    def _add_accounts_args(parser: ArgumentParser) -> None:
        parser.add_argument("-a", "--accounts", type=str, help="comma-separated list of target accounts")

    @staticmethod
    def _add_enforce_arg(parser: ArgumentParser, cmd_help: str) -> None:
        parser.add_argument("-e", "--enforce", action="store_true", help=cmd_help)

    @staticmethod
    def _add_athena_task_args(parser: ArgumentParser) -> None:
        parser.add_argument("-y", "--year", type=int, required=True, help="year for AWS Athena data partition")
        parser.add_argument("-m", "--month", type=int, required=True, help="month for AWS Athena data partition")
        parser.add_argument("-re", "--region", type=str, help="region for AWS Athena data partition")
        AwsScannerArgumentParser._add_accounts_args(parser)

    @staticmethod
    def _add_verbosity_arg(parser: ArgumentParser) -> None:
        parser.add_argument(
            "-v",
            "--verbosity",
            choices=["error", "warning", "info", "debug"],
            default="error",
            help="log level configuration",
        )

    def _build_parser(self) -> ArgumentParser:
        parser = ArgumentParser()
        subparsers = parser.add_subparsers(dest="task", required=True)
        self._add_service_usage_command(subparsers)
        self._add_role_usage_command(subparsers)
        self._add_find_principal_command(subparsers)
        self._add_list_accounts_command(subparsers)
        self._add_list_ssm_parameters_command(subparsers)
        self._add_create_table_command(subparsers)
        self._add_drop_command(subparsers)
        self._add_audit_s3_command(subparsers)
        self._add_audit_vpc_flow_logs_command(subparsers)
        self._add_cost_usage_command(subparsers)
        return parser

    def _add_drop_command(self, subparsers: Any) -> None:
        desc = "drop databases and tables created by tasks"
        drop_parser = subparsers.add_parser(AwsScannerCommands.drop, help=desc, description=desc)
        self._add_auth_args(drop_parser)
        self._add_verbosity_arg(drop_parser)

    def _add_audit_s3_command(self, subparsers: Any) -> None:
        desc = "audit S3 bucket compliance"
        audit_parser = subparsers.add_parser(AwsScannerCommands.audit_s3, help=desc, description=desc)
        self._add_auth_args(audit_parser)
        self._add_accounts_args(audit_parser)
        self._add_verbosity_arg(audit_parser)

    def _add_cost_usage_command(self, subparsers: Any) -> None:
        desc = "audit service cost usage"
        audit_parser = subparsers.add_parser(AwsScannerCommands.cost_usage, help=desc, description=desc)
        self._add_auth_args(audit_parser)
        self._add_accounts_args(audit_parser)
        self._add_verbosity_arg(audit_parser)
        audit_parser.add_argument("-s", "--service", type=str, required=True, help="which service to scan cost \
         usage for")

    def _add_audit_vpc_flow_logs_command(self, subparsers: Any) -> None:
        desc = "audit VPC flow logs compliance"
        audit_parser = subparsers.add_parser(AwsScannerCommands.audit_vpc_flow_logs, help=desc, description=desc)
        self._add_auth_args(audit_parser)
        self._add_accounts_args(audit_parser)
        self._add_enforce_arg(audit_parser, "add centralised flow logs to VPCs that don't already have one")
        self._add_verbosity_arg(audit_parser)

    def _add_create_table_command(self, subparsers: Any) -> None:
        desc = "create Athena table"
        table_parser = subparsers.add_parser(AwsScannerCommands.create_table, help=desc, description=desc)
        self._add_auth_args(table_parser)
        self._add_athena_task_args(table_parser)
        self._add_verbosity_arg(table_parser)

    def _add_list_accounts_command(self, subparsers: Any) -> None:
        desc = "list organization accounts"
        list_accounts_parser = subparsers.add_parser(AwsScannerCommands.list_accounts, help=desc, description=desc)
        self._add_auth_args(list_accounts_parser)
        self._add_verbosity_arg(list_accounts_parser)

    def _add_list_ssm_parameters_command(self, subparsers: Any) -> None:
        desc = "list SSM parameters"
        list_params_parser = subparsers.add_parser(AwsScannerCommands.list_ssm_parameters, help=desc, description=desc)
        self._add_auth_args(list_params_parser)
        self._add_accounts_args(list_params_parser)
        self._add_verbosity_arg(list_params_parser)

    def _add_find_principal_command(self, subparsers: Any) -> None:
        desc = "find principal by source IP"
        principal_parser = subparsers.add_parser(AwsScannerCommands.find_principal, help=desc, description=desc)
        self._add_auth_args(principal_parser)
        self._add_athena_task_args(principal_parser)
        principal_parser.add_argument("-i", "--ip", type=str, required=True, help="source IP of principal to find")
        self._add_verbosity_arg(principal_parser)

    def _add_role_usage_command(self, subparsers: Any) -> None:
        desc = "scan AWS role usage"
        role_parser = subparsers.add_parser(AwsScannerCommands.role_usage, help=desc, description=desc)
        self._add_auth_args(role_parser)
        self._add_athena_task_args(role_parser)
        role_parser.add_argument("-r", "--role", type=str, required=True, help="which role to scan usage for")
        self._add_verbosity_arg(role_parser)

    def _add_service_usage_command(self, subparsers: Any) -> None:
        desc = "scan AWS service usage"
        service_parser = subparsers.add_parser(AwsScannerCommands.service_usage, help=desc, description=desc)
        self._add_auth_args(service_parser)
        self._add_athena_task_args(service_parser)
        service_parser.add_argument("-s", "--service", type=str, required=True, help="which service to scan usage for")
        self._add_verbosity_arg(service_parser)

    def parse_cli_args(self) -> AwsScannerArguments:
        return self._parse_args()

    def parse_lambda_args(self, lambda_event: Dict[str, Any]) -> AwsScannerArguments:
        args = dict(lambda_event, **{"username": SERVICE_ACCOUNT_USER, "token": SERVICE_ACCOUNT_TOKEN})
        command = reduce(lambda cmd, arg: cmd + [f"--{arg[0]}", str(arg[1])], args.items(), [args.pop("task", "")])
        return self._parse_args(command)

    def _parse_args(self, command: Optional[List[str]] = None) -> AwsScannerArguments:
        return self._build_args(vars(self._build_parser().parse_args(command)))

    @staticmethod
    def _build_args(args: Dict[str, Any]) -> AwsScannerArguments:
        return AwsScannerArguments(
            username=args.get("username") or Config().user_name(),
            mfa_token=str(args.get("token")),
            task=str(args.get("task")),
            year=int(args.get("year", -1)),
            month=int(args.get("month", -1)),
            region=args.get("region") or Config().cloudtrail_region(),
            accounts=args.get("accounts", "").split(",") if args.get("accounts") else None,
            service=str(args.get("service")),
            role=str(args.get("role")),
            source_ip=str(args.get("ip")),
            log_level=str(args.get("verbosity")).upper(),
            enforce=bool(args.get("enforce")),
        )
