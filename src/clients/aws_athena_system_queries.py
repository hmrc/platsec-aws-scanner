CREATE_DATABASE = "CREATE DATABASE `$database_name`"

DROP_DATABASE = "DROP DATABASE `$database_name`"

CREATE_TABLE = (
    "CREATE EXTERNAL TABLE `$account` ("
    "`eventversion` string COMMENT 'from deserializer',"
    "`useridentity` struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:"
    "string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,"
    "sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>> "
    "COMMENT 'from deserializer',"
    "`eventtime` string COMMENT 'from deserializer',"
    "`eventsource` string COMMENT 'from deserializer',"
    "`eventname` string COMMENT 'from deserializer',"
    "`awsregion` string COMMENT 'from deserializer',"
    "`sourceipaddress` string COMMENT 'from deserializer',"
    "`useragent` string COMMENT 'from deserializer',"
    "`errorcode` string COMMENT 'from deserializer',"
    "`errormessage` string COMMENT 'from deserializer',"
    "`requestparameters` string COMMENT 'from deserializer',"
    "`responseelements` string COMMENT 'from deserializer',"
    "`additionaleventdata` string COMMENT 'from deserializer',"
    "`requestid` string COMMENT 'from deserializer',"
    "`eventid` string COMMENT 'from deserializer',"
    "`resources` array<struct<arn:string,accountid:string,type:string>> COMMENT 'from deserializer',"
    "`eventtype` string COMMENT 'from deserializer',"
    "`apiversion` string COMMENT 'from deserializer',"
    "`readonly` string COMMENT 'from deserializer',"
    "`recipientaccountid` string COMMENT 'from deserializer',"
    "`serviceeventdetails` string COMMENT 'from deserializer',"
    "`sharedeventid` string COMMENT 'from deserializer',"
    "`vpcendpointid` string COMMENT 'from deserializer') "
    "PARTITIONED BY (`region` string, `year` string, `month` string) "
    "ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde' "
    "STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat' "
    "OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat' "
    "LOCATION 's3://$cloudtrail_logs_bucket/AWSLogs/$account/CloudTrail/' "
    "TBLPROPERTIES ('classification'='cloudtrail')"
)

DROP_TABLE = "DROP TABLE `$table`"

ADD_PARTITION_YEAR_MONTH = (
    "ALTER TABLE `$account` ADD PARTITION (region='$region', year='$year', month='$month') LOCATION "
    "'s3://$cloudtrail_logs_bucket/AWSLogs/$account/CloudTrail/$region/$year/$month'"
)
