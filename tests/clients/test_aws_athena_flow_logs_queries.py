CREATE_TABLE_WITH_YEAR_MONTH_PARTITION = (
    "CREATE EXTERNAL TABLE `flow_logs_2020_11` ("
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
    "`log_status` string,"
    "`vpc-id` string,"
    "`traffic-path` int,"
    "`tcp-flags` int,"
    "`subnet-id` string,"
    "`region` string,"
    "`flow-direction` string,"
    "`pkt-src-aws-service` string,"
    "`pkt-srcaddr` string,"
    "`pkt-dst-aws-service` string,"
    "`pkt-dstaddr` string,"
    "`sublocation-id` string,"
    "`sublocation-type` string,"
    "`instance-id` string,"
    "`type` string,"
    "`az-id` string) "
    "PARTITIONED BY (`year` string, `month` string) "
    "ROW FORMAT DELIMITED "
    "FIELDS TERMINATED BY ' ' "
    "LOCATION 's3://the-flow-logs-bucket/'"
)

CREATE_TABLE_WITH_YEAR_MONTH_DAY_PARTITION = (
    "CREATE EXTERNAL TABLE `flow_logs_2020_10_30` ("
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
    "`log_status` string,"
    "`vpc-id` string,"
    "`traffic-path` int,"
    "`tcp-flags` int,"
    "`subnet-id` string,"
    "`region` string,"
    "`flow-direction` string,"
    "`pkt-src-aws-service` string,"
    "`pkt-srcaddr` string,"
    "`pkt-dst-aws-service` string,"
    "`pkt-dstaddr` string,"
    "`sublocation-id` string,"
    "`sublocation-type` string,"
    "`instance-id` string,"
    "`type` string,"
    "`az-id` string) "
    "PARTITIONED BY (`date` date) "
    "ROW FORMAT DELIMITED "
    "FIELDS TERMINATED BY ' ' "
    "LOCATION 's3://the-flow-logs-bucket/'"
)

ADD_PARTITION_YEAR_MONTH = (
    "ALTER TABLE `flow_logs_2020_09` "
    "ADD PARTITION (year='2020', month='09') "
    "LOCATION 's3://the-flow-logs-bucket/2020/09'"
)

ADD_PARTITION_YEAR_MONTH_DAY = (
    "ALTER TABLE `flow_logs_2020_09_29` "
    "ADD PARTITION (date='2020-09-29') "
    "LOCATION 's3://the-flow-logs-bucket/2020/09/29'"
)
