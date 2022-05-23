GET_USAGE_COST_SUCCESS = {
    "GroupDefinitions": [{"Type": "DIMENSION", "Key": "SERVICE"}, {"Type": "DIMENSION", "Key": "REGION"}],
    "ResultsByTime": [
        {
            "TimePeriod": {"Start": "2020-10-01", "End": "2020-11-02"},
            "Total": {},
            "Groups": [
                {
                    "Keys": ["ap-northeast-1", "AWS CloudTrail"],
                    "Metrics": {
                        "AmortizedCost": {"Amount": "0.0000035", "Unit": "USD"},
                        "UsageQuantity": {"Amount": "389", "Unit": "N/A"},
                    },
                },
                {
                    "Keys": ["eu-west-2", "AWS CloudTrail"],
                    "Metrics": {
                        "AmortizedCost": {"Amount": "0.0000035", "Unit": "USD"},
                        "UsageQuantity": {"Amount": "389", "Unit": "N/A"},
                    },
                },
                {
                    "Keys": ["eu-west-2", "Amazon DynamoDB"],
                    "Metrics": {
                        "AmortizedCost": {"Amount": "0.0000035", "Unit": "USD"},
                        "UsageQuantity": {"Amount": "389", "Unit": "N/A"},
                    },
                },
            ],
            "Estimated": True,
        },
        {
            "TimePeriod": {"Start": "2020-09-01", "End": "2020-10-02"},
            "Total": {},
            "Groups": [
                {
                    "Keys": [
                        "eu-west-2",
                        "Amazon DynamoDB",
                    ],
                    "Metrics": {
                        "AmortizedCost": {"Amount": "1.0000035", "Unit": "USD"},
                        "UsageQuantity": {"Amount": "389", "Unit": "N/A"},
                    },
                },
            ],
            "Estimated": True,
        },
    ],
    "DimensionValueAttributes": [],
}
