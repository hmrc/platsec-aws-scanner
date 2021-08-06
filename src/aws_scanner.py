from typing import Sequence

from src.aws_task_builder import AwsTaskBuilder
from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.data.aws_task_report import AwsTaskReport
from src.aws_task_runner import AwsTaskRunner


class AwsScanner:
    def __init__(self, task_builder: AwsTaskBuilder, task_runner: AwsTaskRunner):
        self._task_builder = task_builder
        self._task_runner = task_runner

    def scan_service_usage(self, partition: AwsAthenaDataPartition, service: str) -> Sequence[AwsTaskReport]:
        return self._task_runner.run(self._task_builder.service_usage_scanner_tasks(partition, service))

    def scan_role_usage(self, partition: AwsAthenaDataPartition, role: str) -> Sequence[AwsTaskReport]:
        return self._task_runner.run(self._task_builder.role_usage_scanner_tasks(partition, role))

    def find_principal_by_ip(self, partition: AwsAthenaDataPartition, source_ip: str) -> Sequence[AwsTaskReport]:
        return self._task_runner.run(self._task_builder.principal_by_ip_finder_tasks(partition, source_ip))

    def create_table(self, partition: AwsAthenaDataPartition) -> Sequence[AwsTaskReport]:
        return self._task_runner.run(self._task_builder.create_athena_table_tasks(partition))

    def list_accounts(self) -> Sequence[AwsTaskReport]:
        return self._task_runner.run(self._task_builder.list_accounts_tasks())

    def list_ssm_parameters(self) -> Sequence[AwsTaskReport]:
        return self._task_runner.run(self._task_builder.list_ssm_parameters_tasks())

    def clean_athena(self) -> Sequence[AwsTaskReport]:
        return self._task_runner.run(self._task_builder.clean_athena_tasks())

    def audit_s3(self) -> Sequence[AwsTaskReport]:
        return self._task_runner.run(self._task_builder.audit_s3_tasks())

    def audit_vpc_flow_logs(self, enforce: bool) -> Sequence[AwsTaskReport]:
        return self._task_runner.run(self._task_builder.audit_vpc_flow_logs_tasks(enforce))
