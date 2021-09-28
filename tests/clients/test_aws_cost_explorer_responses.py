GET_USAGE_COST_SUCCESS = {
    "GroupDefinitions": [{"Type": "DIMENSION", "Key": "SERVICE"}],
    "ResultsByTime": [
        {
            "TimePeriod": {"Start": "2021-07-01", "End": "2021-08-01"},
            "Total": {
                "AmortizedCost": {"Amount": "50", "Unit": "USD"},
                "UsageQuantity": {"Amount": "25", "Unit": "N/A"},
            },
            "Groups": [],
            "Estimated": False,
        },
        {
            "TimePeriod": {"Start": "2021-08-01", "End": "2021-09-01"},
            "Total": {
                "AmortizedCost": {"Amount": "50", "Unit": "USD"},
                "UsageQuantity": {"Amount": "25", "Unit": "N/A"},
            },
            "Groups": [],
            "Estimated": False,
        },
        {
            "TimePeriod": {"Start": "2021-09-01", "End": "2021-09-24"},
            "Total": {
                "AmortizedCost": {"Amount": "150.0079693265", "Unit": "USD"},
                "UsageQuantity": {"Amount": "11800897.896106498", "Unit": "N/A"},
            },
            "Groups": [],
            "Estimated": True,
        },
    ],
    "DimensionValueAttributes": [],
}
