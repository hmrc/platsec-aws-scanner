CREATE_TABLE_WITH_YEAR_MONTH_PARTITION = (
    "CREATE EXTERNAL TABLE `$table_name` ("
    "`version` int,"
    "`account_id` string,"
    "`interface_id` string,"
    "`srcaddr` string,"
    "`dstaddr` string,"
    "`srcport` int,"
    "`dstport` int,"
    "`protocol` bigint,"
    "`packets` bigint,"
    "`bytes` bigint,"
    "`start` bigint,"
    "`end` bigint,"
    "`action` string,"
    "`log_status` string) "
    "PARTITIONED BY (`year` string, `month` string) "
    "ROW FORMAT DELIMITED "
    "FIELDS TERMINATED BY ' ' "
    "LOCATION 's3://$flow_logs_bucket/'"
)

CREATE_TABLE_WITH_YEAR_MONTH_DAY_PARTITION = (
    "CREATE EXTERNAL TABLE `$table_name` ("
    "`version` int,"
    "`account_id` string,"
    "`interface_id` string,"
    "`srcaddr` string,"
    "`dstaddr` string,"
    "`srcport` int,"
    "`dstport` int,"
    "`protocol` bigint,"
    "`packets` bigint,"
    "`bytes` bigint,"
    "`start` bigint,"
    "`end` bigint,"
    "`action` string,"
    "`log_status` string) "
    "PARTITIONED BY (`date` date) "
    "ROW FORMAT DELIMITED "
    "FIELDS TERMINATED BY ' ' "
    "LOCATION 's3://$flow_logs_bucket/'"
)

ADD_PARTITION_YEAR_MONTH = (
    "ALTER TABLE `$table_name` "
    "ADD PARTITION (year='$year', month='$month') "
    "LOCATION 's3://$flow_logs_bucket/$year/$month'"
)

ADD_PARTITION_YEAR_MONTH_DAY = (
    "ALTER TABLE `$table_name` "
    "ADD PARTITION (date='$year-$month-$day') "
    "LOCATION 's3://$flow_logs_bucket/$year/$month/$day'"
)
