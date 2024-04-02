# Configuration

This tool expects a configuration file named `aws_scanner_config.ini` and located at the root of the project. A template
configuration file that shows how such file should look like [can be found here](../aws_scanner_config_template.ini).
Refer to [Requirements][doc-requirements] for details on how the AWS infrastructure should look like.

Here are details on the different config sections and what they are for:

## Athena

```ini
[athena]
account = 555666777888
role = athena_role
database_prefix = some_prefix
query_results_bucket = query-results-bucket
query_results_polling_delay_seconds = 1
query_timeout_seconds = 600
query_throttling_seconds = 2
```

-   `account`: an account where [CloudTrail logs][aws-cloudtrail] of other AWS accounts are centrally collected
    
-   `role`: name of the role that is assumed to perform Athena-related operations on Cloudtrail logs
    
-   `database_prefix`: when this tool runs [Athena][aws-athena] related tasks, the databases that are created will have
    their names prefixed with this value, to avoid confusion with other databases that might already exist

-   `query_results_bucket`: name of the bucket were results of [Athena queries][aws-athena-querying] will be stored

-   `query_results_polling_delay_seconds`: interval between two query results polls

-   `query_timeout_seconds`: maximum duration a query can run for

-   `query_throttling_seconds`: delay before starting a new query execution

## CloudTrail

```ini
[cloudtrail]
logs_bucket = cloudtrail-logs-bucket
logs_retention_days = 90
region = us-east-1
```

-   `logs_bucket`: name of the bucket were [CloudTrail logs][aws-cloudtrail-bucket] are stored
    
-   `log_retention_days`: number of days before CloudTrail logs are removed from the bucket where they are stored (this
    is used to validate the data partition configuration in [AwsAthenaDataPartition][src-partition])
    
-   `region`: AWS region for partitioning the CloudTrail data in Athena; can be superseded with `-re | --region`
    argument

## CostExplorer

```ini
[cost_explorer]
role = RolePlatformReadOnly
```

`role`: name of the role that is assumed to perform costExplorer-related operations on accounts

## Organization

```ini
[organization]
account = 999888777666
role = orgs_role
include_root_accounts = true
parent = Parent OU
```

-   `account`: an account that consolidates the other AWS accounts through the
    [AWS Organizations service][aws-organizations]

-   `role`: name of the role that is assumed to perform organizations-related operations
    
-   `include_root_accounts`: \[true|false\] indicate whether accounts in the
    [root organizational unit][aws-organizations-root] should be included in the accounts list that tasks will be run
    against

-   `parent`: name of the parent [organizational unit][aws-organizational-ou] that will be targeted by the tasks (i.e.
    all accounts, whether they are part of this parent OU or OUs owned by this OU, will be targeted by the scanning
    tasks)

## Reports

```ini
[reports]
account = 333222333222
bucket = scanner-reports-bucket
output = s3
role = s3_reports_role
```

- `account`: an account with a bucket where scanner reports will be written into
- `bucket`: name of the bucket were scanner reports will be written into
- `output`: \[stdout|s3\] whether scanner reports should be printed in standard output or written in an S3 bucket
- `role`: name of the role that is assumed to write scanner reports in `reports.bucket`

## S3

```ini
[s3]
role = s3_role
```

- `role`: name of the role that is assumed to perform s3-related operations

## Session

```ini
[session]
duration_seconds = 3600
```

- `duration_seconds`: number of seconds during which an assumed-role session is valid

## SSM

```ini
[ssm]
role = ssm_role
```

- `role`: name of the role that is assumed to perform ssm-related operations

## Tasks

```ini
[tasks]
executors = 10
```

- `executors`: number of executors that run tasks in parallel

## User

```ini
[user]
account = 111222333444
name = joe.bloggs
```

- `account`: an account with an IAM user that have delegate access on the roles that are assumed
- `name`: IAM user that is used to assume roles; can be superseded with `-u | --username` argument

[aws-athena]: https://docs.aws.amazon.com/athena/latest/ug/what-is.html
[aws-athena-querying]: https://docs.aws.amazon.com/athena/latest/ug/querying.html
[aws-cloudtrail]: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html
[aws-cloudtrail-bucket]: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html
[aws-organizational-ou]: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_getting-started_concepts.html#organizationalunit
[aws-organizations]: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html
[aws-organizations-root]: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_getting-started_concepts.html#root
[doc-requirements]: ./requirements.md
[src-partition]: ../src/data/aws_athena_data_partition.py
