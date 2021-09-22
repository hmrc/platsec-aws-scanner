GET_USAGE_COST_SUCCESS = {
    "GroupDefinitions": [{"Type": "DIMENSION", "Key": "SERVICE"}],
    "ResultsByTime": [
        {
            "TimePeriod": {"Start": "2021-08-01", "End": "2021-09-01"},
            "Total": {},
            "Groups": [
                {
                    "Keys": ["Lambda"],
                    "Metrics": {
                        "AmortizedCost": {"Amount": "0", "Unit": "USD"},
                        "UsageQuantity": {"Amount": "0", "Unit": "N/A"},
                    },
                },
            ],
            "Estimated": "false",
        }
    ],
    "DimensionValueAttributes": [],
    "ResponseMetadata": {
        "RequestId": "b9cc4c48-ba6f-4934-815d-e722484abab8",
        "HTTPStatusCode": 200,
        "HTTPHeaders": {
            "date": "Mon, 20 Sep 2021 09:52:32 GMT",
            "content-type": "application/x-amz-json-1.1",
            "content-length": "619",
            "connection": "keep-alive",
            "x-amzn-requestid": "b9cc4c48-ba6f-4934-815d-e722484abab8",
            "cache-control": "no-cache",
        },
        "RetryAttempts": 0,
    },
}
