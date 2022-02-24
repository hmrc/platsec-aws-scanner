DROP_DATABASE_EXECUTION_FAILURE = {
    "QueryExecution": {
        "QueryExecutionId": "6da1f9be-772e-4a19-a542-f9f13e037707",
        "Query": "DROP DATABASE `1234`",
        "StatementType": "DDL",
        "ResultConfiguration": {"OutputLocation": "s3://query-results-bucket/[truncated]"},
        "QueryExecutionContext": {"Catalog": "awsdatacatalog"},
        "Status": {
            "State": "FAILED",
            "StateChangeReason": "FAILED: SemanticException [Error 10072]: Database does not exist: 1234",
            "SubmissionDateTime": "datetime.datetime(2021, 2, 3, 15, 2, 30, 150000, tzinfo=tzlocal())",
            "CompletionDateTime": "datetime.datetime(2021, 2, 3, 15, 2, 30, 970000, tzinfo=tzlocal())",
        },
        "Statistics": {
            "EngineExecutionTimeInMillis": 234,
            "DataScannedInBytes": 0,
            "TotalExecutionTimeInMillis": 820,
            "QueryQueueTimeInMillis": 565,
            "ServiceProcessingTimeInMillis": 21,
        },
        "WorkGroup": "primary",
    },
    "ResponseMetadata": {
        "RequestId": "f95bde03-f797-4df2-a809-216e82e423e8",
        "HTTPStatusCode": 200,
        "HTTPHeaders": {
            "content-type": "application/x-amz-json-1.1",
            "date": "Wed, 03 Feb 2021 15:02:35 GMT",
            "x-amzn-requestid": "f95bde03-f797-4df2-a809-216e82e423e8",
            "content-length": "1641",
            "connection": "keep-alive",
        },
        "RetryAttempts": 0,
    },
}

GET_EVENT_USAGE_COUNT_RESULTS = {
    "UpdateCount": 0,
    "ResultSet": {
        "Rows": [
            {"Data": [{"VarCharValue": "eventname"}, {"VarCharValue": "usage_count"}]},
            {"Data": [{"VarCharValue": "GetParameter"}, {"VarCharValue": "274"}]},
            {"Data": [{"VarCharValue": "DescribeInstanceInformation"}, {"VarCharValue": "1"}]},
            {"Data": [{"VarCharValue": "GetParameters"}, {"VarCharValue": "570"}]},
            {"Data": [{"VarCharValue": "ListAssociations"}, {"VarCharValue": "1"}]},
        ],
        "ResultSetMetadata": {
            "ColumnInfo": [
                {
                    "CatalogName": "hive",
                    "SchemaName": "",
                    "TableName": "",
                    "Name": "eventname",
                    "Label": "eventname",
                    "Type": "varchar",
                    "Precision": 2147483647,
                    "Scale": 0,
                    "Nullable": "UNKNOWN",
                    "CaseSensitive": True,
                },
                {
                    "CatalogName": "hive",
                    "SchemaName": "",
                    "TableName": "",
                    "Name": "usage_count",
                    "Label": "usage_count",
                    "Type": "bigint",
                    "Precision": 19,
                    "Scale": 0,
                    "Nullable": "UNKNOWN",
                    "CaseSensitive": False,
                },
            ]
        },
    },
    "ResponseMetadata": {
        "RequestId": "99c8c825-879b-4bab-9c38-580f1ce6bef3",
        "HTTPStatusCode": 200,
        "HTTPHeaders": {
            "content-type": "application/x-amz-json-1.1",
            "date": "Mon, 08 Feb 2021 12:13:55 GMT",
            "x-amzn-requestid": "99c8c825-879b-4bab-9c38-580f1ce6bef3",
            "content-length": "827",
            "connection": "keep-alive",
        },
        "RetryAttempts": 0,
    },
}

GET_EVENT_USAGE_COUNT_EMPTY_RESULTS = {
    "UpdateCount": 0,
    "ResultSet": {
        "Rows": [{"Data": [{"VarCharValue": "eventname"}, {"VarCharValue": "usage_count"}]}],
        "ResultSetMetadata": {
            "ColumnInfo": [
                {
                    "CatalogName": "hive",
                    "SchemaName": "",
                    "TableName": "",
                    "Name": "eventname",
                    "Label": "eventname",
                    "Type": "varchar",
                    "Precision": 2147483647,
                    "Scale": 0,
                    "Nullable": "UNKNOWN",
                    "CaseSensitive": True,
                },
                {
                    "CatalogName": "hive",
                    "SchemaName": "",
                    "TableName": "",
                    "Name": "usage_count",
                    "Label": "usage_count",
                    "Type": "bigint",
                    "Precision": 19,
                    "Scale": 0,
                    "Nullable": "UNKNOWN",
                    "CaseSensitive": False,
                },
            ]
        },
    },
    "ResponseMetadata": {
        "RequestId": "df06d000-25c7-44be-8569-5df438effc16",
        "HTTPStatusCode": 200,
        "HTTPHeaders": {
            "content-type": "application/x-amz-json-1.1",
            "date": "Tue, 09 Feb 2021 16:31:29 GMT",
            "x-amzn-requestid": "df06d000-25c7-44be-8569-5df438effc16",
            "content-length": "547",
            "connection": "keep-alive",
        },
        "RetryAttempts": 0,
    },
}
