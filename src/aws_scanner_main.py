import logging

from typing import Any, Callable, Dict, Tuple

from src.aws_parallel_task_runner import AwsParallelTaskRunner
from src.aws_scanner_output import AwsScannerOutput
from src.aws_task_builder import AwsTaskBuilder
from src.clients.aws_client_factory import AwsClientFactory
from src.aws_scanner import AwsScanner
from src.aws_scanner_argument_parser import AwsScannerArguments
from src.aws_scanner_argument_parser import AwsScannerCommands as Commands
from src.data.aws_scanner_exceptions import AwsScannerException


class AwsScannerMain:
    def __init__(self, args: AwsScannerArguments) -> None:
        self._main(args)

    def _main(self, args: AwsScannerArguments) -> None:
        logger = self._configure_logging(args)
        try:
            scanner, output = self._build_aws_scanner(args)
            reports = self._get_tasks_mapping(scanner, args)[args.task]()
            output.write(args.task, reports)
        except AwsScannerException as ex:
            logger.error(f"{type(ex).__name__}: {ex}")
            raise SystemExit(1)

    def _configure_logging(self, args: AwsScannerArguments) -> logging.Logger:
        logging.basicConfig(
            level=args.log_level,
            datefmt="%Y-%m-%dT%H:%M:%S",
            format="%(asctime)s %(levelname)s %(module)s %(message)s",
        )
        logging.getLogger().setLevel(args.log_level)
        logging.getLogger("botocore").setLevel(logging.ERROR)
        logging.getLogger("urllib3").setLevel(logging.ERROR)
        logging.getLogger("requests").setLevel(logging.ERROR)
        return logging.getLogger(self.__class__.__name__)

    @staticmethod
    def _build_aws_scanner(args: AwsScannerArguments) -> Tuple[AwsScanner, AwsScannerOutput]:
        factory = AwsClientFactory(mfa=args.mfa_token, username=args.username)
        task_builder = AwsTaskBuilder(factory.get_organizations_client(), args.accounts)
        task_runner = AwsParallelTaskRunner(factory)
        return AwsScanner(task_builder, task_runner), AwsScannerOutput(factory)

    @staticmethod
    def _get_tasks_mapping(scanner: AwsScanner, args: AwsScannerArguments) -> Dict[str, Callable[[], Any]]:
        return {
            Commands.service_usage: lambda: scanner.scan_service_usage(args.partition, args.service),
            Commands.role_usage: lambda: scanner.scan_role_usage(args.partition, args.role),
            Commands.find_principal: lambda: scanner.find_principal_by_ip(args.partition, args.source_ip),
            Commands.create_table: lambda: scanner.create_table(args.partition),
            Commands.list_accounts: lambda: scanner.list_accounts(),
            Commands.list_ssm_parameters: lambda: scanner.list_ssm_parameters(),
            Commands.drop: lambda: scanner.clean_athena(),
            Commands.audit_s3: lambda: scanner.audit_s3(),
            Commands.audit_vpc_flow_logs: lambda: scanner.audit_vpc_flow_logs(args.enforce),
        }
