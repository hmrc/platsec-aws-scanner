from pickle import TRUE
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
    ],
}

EXPECTED_LIST_HOSTED_ZONES_PRIVATE: Dict[str, Any] = {
    "HostedZones": [
        {
            "Id": "/hostedzone/AAAABBBBCCCCDD",
            "Name": "public.aws.scanner.gov.uk.",
            "CallerReference": "string",
            "Config": {"Comment": "string", "PrivateZone": True},
            "ResourceRecordSetCount": 123,
            "LinkedService": {"ServicePrincipal": "string", "Description": "string"},
        },
        {
            "Id": "/hostedzone/EEEEFFFFGGGGHH",
            "Name": "private.aws.scanner.gov.uk.",
            "CallerReference": "string",
            "Config": {"Comment": "string", "PrivateZone": TRUE},
            "ResourceRecordSetCount": 123,
            "LinkedService": {"ServicePrincipal": "string", "Description": "string"},
        },
    ],
}

EXPECTED_LIST_HOSTED_ZONES_PUBLIC: Dict[str, Any] = {
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
            "Config": {"Comment": "string", "PrivateZone": False},
            "ResourceRecordSetCount": 123,
            "LinkedService": {"ServicePrincipal": "string", "Description": "string"},
        },
    ],
}