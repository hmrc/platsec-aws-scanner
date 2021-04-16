CREATE_TABLE_EXECUTION_SUCCESS = {
    "QueryExecution": {
        "QueryExecutionId": "48068afb-edde-4e9c-bcef-6bfa29987b1a",
        "Query": "CREATE EXTERNAL TABLE `132732819912` (`eventversion` string COMMENT 'from deserializer',[truncated]",
        "StatementType": "DDL",
        "ResultConfiguration": {
            "OutputLocation": "s3://query-results-bucket/[truncated]",
        },
        "QueryExecutionContext": {"Database": "boto3_db_20210201144511", "Catalog": "awsdatacatalog"},
        "Status": {
            "State": "SUCCEEDED",
            "SubmissionDateTime": "datetime.datetime(2021, 2, 3, 10, 59, 19, 777000, tzinfo=tzlocal())",
            "CompletionDateTime": "datetime.datetime(2021, 2, 3, 10, 59, 20, 332000, tzinfo=tzlocal())",
        },
        "Statistics": {
            "EngineExecutionTimeInMillis": 451,
            "DataScannedInBytes": 0,
            "TotalExecutionTimeInMillis": 555,
            "QueryQueueTimeInMillis": 74,
            "ServiceProcessingTimeInMillis": 30,
        },
        "WorkGroup": "primary",
    },
    "ResponseMetadata": {
        "RequestId": "47578602-b0ce-4eb1-9c9b-1be124948b54",
        "HTTPStatusCode": 200,
        "HTTPHeaders": {
            "content-type": "application/x-amz-json-1.1",
            "date": "Wed, 03 Feb 2021 10:59:24 GMT",
            "x-amzn-requestid": "47578602-b0ce-4eb1-9c9b-1be124948b54",
            "content-length": "5390",
            "connection": "keep-alive",
        },
        "RetryAttempts": 0,
    },
}

CREATE_TABLE_RESULTS = {
    "ResultSet": {"Rows": [], "ResultSetMetadata": {"ColumnInfo": []}},
    "ResponseMetadata": {
        "RequestId": "17b4cca1-7385-4ccc-bf96-a6f7c2a8b718",
        "HTTPStatusCode": 200,
        "HTTPHeaders": {
            "content-type": "application/x-amz-json-1.1",
            "date": "Wed, 03 Feb 2021 10:59:24 GMT",
            "x-amzn-requestid": "17b4cca1-7385-4ccc-bf96-a6f7c2a8b718",
            "content-length": "108",
            "connection": "keep-alive",
        },
        "RetryAttempts": 0,
    },
}

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

DROP_DATABASE_RESULTS_FAILURE = {
    "ResponseMetadata": {
        "RequestId": "7ccc6116-1699-4be4-965d-daf9b0340c12",
        "HTTPStatusCode": 200,
        "HTTPHeaders": {
            "content-type": "application/x-amz-json-1.1",
            "date": "Wed, 03 Feb 2021 15:02:34 GMT",
            "x-amzn-requestid": "7ccc6116-1699-4be4-965d-daf9b0340c12",
            "content-length": "83",
            "connection": "keep-alive",
        },
        "RetryAttempts": 0,
    }
}

GET_SERVICE_USAGE_COUNT_RESULTS = {
    "UpdateCount": 0,
    "ResultSet": {
        "Rows": [{"Data": [{"VarCharValue": "ssm_usage"}]}, {"Data": [{"VarCharValue": "846"}]}],
        "ResultSetMetadata": {
            "ColumnInfo": [
                {
                    "CatalogName": "hive",
                    "SchemaName": "",
                    "TableName": "",
                    "Name": "ssm_usage",
                    "Label": "ssm_usage",
                    "Type": "bigint",
                    "Precision": 19,
                    "Scale": 0,
                    "Nullable": "UNKNOWN",
                    "CaseSensitive": False,
                }
            ]
        },
    },
    "ResponseMetadata": {
        "RequestId": "7ac6caaf-02bb-438c-85b1-8bc90a23fd24",
        "HTTPStatusCode": 200,
        "HTTPHeaders": {
            "content-type": "application/x-amz-json-1.1",
            "date": "Mon, 08 Feb 2021 12:03:39 GMT",
            "x-amzn-requestid": "7ac6caaf-02bb-438c-85b1-8bc90a23fd24",
            "content-length": "361",
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
