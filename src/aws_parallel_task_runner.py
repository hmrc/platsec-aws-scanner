from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Any, Dict, Optional, Sequence

from src.data.aws_task_report import AwsTaskReport
from src.aws_task_runner import AwsTaskRunner
from src.aws_scanner_config import AwsScannerConfig as Config
from src.data.aws_scanner_exceptions import AwsScannerException
from src.tasks.aws_task import AwsTask


class AwsParallelTaskRunner(AwsTaskRunner):
    def _run_tasks(self, tasks: Sequence[AwsTask]) -> Sequence[AwsTaskReport]:
        with ThreadPoolExecutor(max_workers=Config().tasks_executors()) as executor:
            futures = {executor.submit(self._run_task, task): task for task in tasks}
        return list(filter(None, [self._get_result(future, futures) for future in as_completed(futures)]))

    def _get_result(
        self, future: Future[AwsTaskReport], all_futures: Dict[Future[AwsTaskReport], Any]
    ) -> Optional[AwsTaskReport]:
        try:
            return future.result()
        except AwsScannerException as ex:
            self._logger.error(f"{all_futures[future]} failed with: '{ex}'")
        return None
