from logging import getLogger
from typing import Sequence

from botocore.client import BaseClient

from src.clients import boto_try
from src.data.aws_cloudtrail_types import EventSelector, Trail, to_event_selector, to_trail


class AwsCloudtrailClient:
    def __init__(self, cloudtrail: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self.cloudtrail = cloudtrail

    def get_trails(self) -> Sequence[Trail]:
        return [self._enrich_trail(trail) for trail in self._describe_trails()]

    def _enrich_trail(self, trail: Trail) -> Trail:
        trail.is_logging = self._get_trail_logging(trail)
        trail.event_selectors = self._get_event_selectors(trail)
        return trail

    def _describe_trails(self) -> Sequence[Trail]:
        return boto_try(
            lambda: [to_trail(t) for t in self.cloudtrail.describe_trails()["trailList"]],
            list,
            "unable to describe trails",
        )

    def _get_trail_logging(self, trail: Trail) -> bool:
        return boto_try(
            lambda: bool(self.cloudtrail.get_trail_status(Name=trail.name)["IsLogging"]),
            bool,
            f"unable to get trail status for trail {trail.name}",
        )

    def _get_event_selectors(self, trail: Trail) -> Sequence[EventSelector]:
        return boto_try(
            lambda: [
                to_event_selector(es)
                for es in self.cloudtrail.get_event_selectors(TrailName=trail.name)["EventSelectors"]
            ],
            list,
            f"unable to get event selectors for trail {trail.name}",
        )
