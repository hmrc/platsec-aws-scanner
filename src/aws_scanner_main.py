import logging

from src.aws_parallel_task_runner import AwsParallelTaskRunner
from src.aws_scanner_output import AwsScannerOutput
from src.aws_task_builder import AwsTaskBuilder
from src.clients.aws_client_factory import AwsClientFactory
from src.aws_scanner_argument_parser import AwsScannerArguments
from src.data.aws_scanner_exceptions import AwsScannerException


class AwsScannerMain:
    def __init__(self, args: AwsScannerArguments) -> None:
        self._main(args)

    def _main(self, args: AwsScannerArguments) -> None:
        logger = self._configure_logging(args)
        try:
            factory = AwsClientFactory(mfa=args.mfa_token, username=args.username, region=args.region)
            tasks = AwsTaskBuilder(factory, args).build_tasks()
            reports = AwsParallelTaskRunner(factory).run(tasks)
            AwsScannerOutput(factory).write(args.task, reports)
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
