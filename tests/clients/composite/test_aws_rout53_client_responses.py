from typing import Dict, Any


EXPECTED_LIST_HOSTED_ZONES: Dict[str, Any] = {
    "HostedZones": [
        {
            "Id": "/hostedzone/AAAABBBBCCCCDD",
            "Name": "public.aws.scanner.gov.uk.",
            "CallerReference": "string",
            "Config": {"Comment": "string", "PrivateZone": False},
            "ResourceRecordSetCount": 123,
            "LinkedService": {"ServicePrincipal": "string", "Description": "string"},
        },
        {
            "Id": "/hostedzone/EEEEFFFFGGGGHH",
            "Name": "private.aws.scanner.gov.uk.",
            "CallerReference": "string",
            "Config": {"Comment": "string", "PrivateZone": True},
            "ResourceRecordSetCount": 123,
            "LinkedService": {"ServicePrincipal": "string", "Description": "string"},
        },
        {
            "Id": "/hostedzone/IIIIIIILLLLLLL",
            "Name": "public.aws.scanner.gov.uk.",
            "CallerReference": "string",
            "Config": {"Comment": "string", "PrivateZone": False},
            "ResourceRecordSetCount": 123,
            "LinkedService": {"ServicePrincipal": "string", "Description": "string"},
        },
    ],
}

EXPECTED_QUERY_LOG: Dict[str, Any] = {
    "QueryLoggingConfigs": [
        {
            "Id": "abcdefgh-1234-5678-90ab-ijklmnopqrst",
            "HostedZoneId": "AAAABBBBCCCCDD",
            "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:\
log-group:/aws/route53/public.aws.scanner.gov.uk.",
        }
    ]
}

EXPECTED_EMPTY_QUERY_LOG: Dict[str, Any] = {"QueryLoggingConfigs": []}
