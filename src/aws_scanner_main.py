from logging import getLogger
from typing import Any, Callable, Dict

from src.aws_parallel_task_runner import AwsParallelTaskRunner
from src.aws_task_builder import AwsTaskBuilder
from src.clients.aws_client_factory import AwsClientFactory
from src.aws_scanner import AwsScanner
from src.aws_scanner_argument_parser import AwsScannerArgumentParser, AwsScannerArguments
from src.aws_scanner_argument_parser import AwsScannerCommands as Commands
from src.data.aws_scanner_exceptions import AwsScannerException
from src.json_serializer import to_json


class AwsScannerMain:
    def __init__(self) -> None:
        self._logger = getLogger(self.__class__.__name__)
        self._main()

    def _main(self) -> None:
        args = AwsScannerArgumentParser().parse_args()
        try:
            print(to_json(self._get_tasks_mapping(self._build_aws_scanner(args), args)[args.task]()))
        except AwsScannerException as ex:
            self._logger.error(f"{type(ex).__name__}: {ex}")
            raise SystemExit(1)

    @staticmethod
    def _build_aws_scanner(args: AwsScannerArguments) -> AwsScanner:
        factory = AwsClientFactory(mfa=args.mfa_token, username=args.username)
        task_builder = AwsTaskBuilder(factory.get_organizations_client(), args.accounts)
        task_runner = AwsParallelTaskRunner(factory)
        return AwsScanner(task_builder, task_runner)

    @staticmethod
    def _get_tasks_mapping(scanner: AwsScanner, args: AwsScannerArguments) -> Dict[str, Callable[[], Any]]:
        return {
            Commands.service_usage: lambda: scanner.scan_service_usage(args.year, args.month, args.service),
            Commands.role_usage: lambda: scanner.scan_role_usage(args.year, args.month, args.role),
            Commands.find_principal: lambda: scanner.find_principal_by_ip(args.year, args.month, args.source_ip),
            Commands.create_table: lambda: scanner.create_table(args.year, args.month),
            Commands.list_accounts: lambda: scanner.list_accounts(),
            Commands.list_ssm_parameters: lambda: scanner.list_ssm_parameters(),
            Commands.drop: lambda: scanner.clean_athena(),
        }
