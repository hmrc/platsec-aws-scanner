from typing import Dict, Any

import src.data.aws_route53_types as route53Type

EXPECTED_LIST_HOSTED_ZONES: Dict[Any, Any] = {
    "/hostedzone/AAAABBBBCCCCDD": route53Type.Route53Zone(
        id="/hostedzone/AAAABBBBCCCCDD",
        name="public.aws.scanner.gov.uk.",
        privateZone=False,
        queryLog="arn:aws:logs:us-east-1:123456789012:log-group:/aws/route53/public.aws.scanner.gov.uk.",
    ),
    "/hostedzone/IIIIIIILLLLLLL": route53Type.Route53Zone(
        id="/hostedzone/IIIIIIILLLLLLL",
        name="public.aws.scanner.gov.uk.",
        privateZone=False,
        queryLog="",
    ),
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
