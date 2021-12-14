from logging import getLogger
from typing import Optional, Sequence

from botocore.client import BaseClient

from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients import boto_try
from src.clients.aws_logs_client import AwsLogsClient
from src.data.aws_cloudtrail_types import EventSelector, Trail, to_event_selector, to_trail
from src.data.aws_logs_types import LogGroup


class AwsCloudtrailClient:
    def __init__(self, cloudtrail: BaseClient, logs: AwsLogsClient):
        self._logger = getLogger(self.__class__.__name__)
        self._config = Config()
        self._cloudtrail = cloudtrail
        self._logs = logs

    def get_trails(self) -> Sequence[Trail]:
        return [self._enrich_trail(trail) for trail in self._describe_trails()]

    def get_cloudtrail_log_group(self) -> Optional[LogGroup]:
        log_group = filter(
            lambda g: g.name == self._config.cloudtrail_log_group_name(),
            self._logs.describe_log_groups(self._config.cloudtrail_log_group_name()),
        )
        return next(log_group, None)

    def _enrich_trail(self, trail: Trail) -> Trail:
        trail.is_logging = self._get_trail_logging(trail)
        trail.event_selectors = self._get_event_selectors(trail)
        return trail

    def _describe_trails(self) -> Sequence[Trail]:
        return boto_try(
            lambda: [to_trail(t) for t in self._cloudtrail.describe_trails()["trailList"]],
            list,
            "unable to describe trails",
        )

    def _get_trail_logging(self, trail: Trail) -> bool:
        return boto_try(
            lambda: bool(self._cloudtrail.get_trail_status(Name=trail.name)["IsLogging"]),
            bool,
            f"unable to get trail status for trail {trail.name}",
        )

    def _get_event_selectors(self, trail: Trail) -> Sequence[EventSelector]:
        return boto_try(
            lambda: [
                to_event_selector(es)
                for es in self._cloudtrail.get_event_selectors(TrailName=trail.name)["EventSelectors"]
            ],
            list,
            f"unable to get event selectors for trail {trail.name}",
        )
