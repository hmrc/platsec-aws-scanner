from logging import getLogger
from typing import Any, Dict, Sequence, List, Optional
from itertools import chain

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

import  src.data.aws_route53_types as route53Type
from src.aws_scanner_config import AwsScannerConfig as Config
from src.data.aws_scanner_exceptions import QueryLogException


class AwsHostedZonesClient:
    def __init__(self, boto_route53: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._config = Config()
        self._route53 = boto_route53

    def list_hosted_zones(self) -> Dict[Any, Any]:
        public_zones: Dict[Any, Any] = {}
        hostedzones = self._route53.list_hosted_zones()["HostedZones"]
        for host in hostedzones:
            zone = route53Type.to_route53Zone(host)
            if not zone.privateZone:
                queryLogConfig = self._route53.list_query_logging_configs(HostedZoneId= zone.id.replace("/hostedzone/", ""))
                if len(queryLogConfig) > 0 and len(queryLogConfig["QueryLoggingConfigs"]) > 0:
                    zone.queryLog = queryLogConfig["QueryLoggingConfigs"][0]["CloudWatchLogsLogGroupArn"]
                public_zones[zone.id] = zone

        return public_zones
       
    def list_query_logging_configs(self, id: str) -> Any:
        try:
            return self._route53.list_query_logging_configs(HostedZoneId=id)
        except (BotoCoreError, ClientError) as err:
            raise QueryLogException(f"unable to get the query log config: {err}")

    def create_query_logging_config(self, hosted_zone_id: str, cloudwatch_logs_loggrouparn: str) -> Any:
        hosted_zone_query_log =  self._route53.list_query_logging_configs(HostedZoneId= hosted_zone_id)

        if  len(hosted_zone_query_log["QueryLoggingConfigs"]) == 0 or hosted_zone_query_log["QueryLoggingConfigs"][0]["CloudWatchLogsLogGroupArn"] == "":
            return self._route53.create_query_logging_config(
                HostedZoneId=hosted_zone_id, CloudWatchLogsLogGroupArn=cloudwatch_logs_loggrouparn
        )
        

    def delete_query_logging_config(self, hosted_zone_id: str) -> Any:

        queryLoggingConfig = self._route53.list_query_logging_configs(HostedZoneId =hosted_zone_id) 
        if len(queryLoggingConfig["QueryLoggingConfigs"]) > 0:
             queryLoggingConfigId = queryLoggingConfig["QueryLoggingConfigs"][0]["Id"]
             self._route53.delete_query_logging_config(Id =queryLoggingConfigId) 

        return hosted_zone_id
