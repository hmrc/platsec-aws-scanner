GET_USAGE_COST_SUCCESS = {
    "GroupDefinitions": [{"Type": "DIMENSION", "Key": "SERVICE"}, {"Type": "DIMENSION", "Key": "REGION"}],
    "ResultsByTime": [
        {
            "TimePeriod": {"Start": "2020-02-01", "End": "2020-11-02"},
            "Total": {},
            "Groups": [
                {
                    "Keys": ["AWS CloudTrail", "ap-northeast-1"],
                    "Metrics": {
                        "AmortizedCost": {"Amount": "0.0000035", "Unit": "USD"},
                        "UsageQuantity": {"Amount": "389", "Unit": "N/A"},
                    },
                },
                {
                    "Keys": ["AWS CloudTrail", "eu-west-2"],
                    "Metrics": {
                        "AmortizedCost": {"Amount": "0.0000035", "Unit": "USD"},
                        "UsageQuantity": {"Amount": "389", "Unit": "N/A"},
                    },
                },
                {
                    "Keys": ["Amazon DynamoDB", "eu-west-2"],
                    "Metrics": {
                        "AmortizedCost": {"Amount": "1.0000035", "Unit": "USD"},
                        "UsageQuantity": {"Amount": "389", "Unit": "N/A"},
                    },
                },
                {
                    "Keys": ["Amazon DynamoDB", "eu-west-2"],
                    "Metrics": {
                        "AmortizedCost": {"Amount": "0.0000035", "Unit": "USD"},
                        "UsageQuantity": {"Amount": "389", "Unit": "N/A"},
                    },
                },
            ],
            "Estimated": True,
        }
    ],
    "DimensionValueAttributes": [],
}
