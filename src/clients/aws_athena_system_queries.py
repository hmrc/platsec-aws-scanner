CREATE_DATABASE = "CREATE DATABASE `$database_name`"

DROP_DATABASE = "DROP DATABASE `$database_name`"

DROP_TABLE = "DROP TABLE `$table`"

ADD_PARTITION_YEAR_MONTH = (
    "ALTER TABLE `$account` ADD PARTITION (region='$region', year='$year', month='$month') LOCATION "
    "'s3://$cloudtrail_logs_bucket/AWSLogs/$account/CloudTrail/$region/$year/$month'"
)
