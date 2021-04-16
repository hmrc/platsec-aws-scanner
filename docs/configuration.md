# Configuration

This tool expects a configuration file named `aws_scanner_config.ini` and located at the root of the project. A template
configuration file that shows how such file should look like [can be found here](../aws_scanner_config_template.ini).

Here are details on the different config sections and what they are for:

## Accounts

```ini
[accounts]
auth = 111222333444
cloudtrail = 555666777888
root = 999888777666
```

These are identifiers of the AWS accounts that are of interest. Refer to [Requirements][doc-requirements] for details on
how the AWS infrastructure should look like.

- `auth`: an account with IAM users that have delegate access on the roles that are assumed by this tool
- `cloudtrail`: an account where [CloudTrail logs][aws-cloudtrail] of all the other AWS accounts are centrally collected
- `root`: an account that consolidates the other AWS accounts through the [AWS Organizations service][aws-organizations]

## Athena

```ini
[athena]
database_prefix = some_prefix
```

- `database_prefix`: when this tool runs [Athena][aws-athena] related tasks, the databases that are created will have
  their name prefixed with this value, which helps to avoid confusion with other databases that might already exist

## Buckets

```ini
[buckets]
athena_query_results = query-results-bucket
cloudtrail_logs = cloudtrail-logs-bucket
```

- `athena_query_results`: name of the bucket were results of [Athena queries][aws-athena-querying] will be stored
- `cloudtrail_logs`: name of the bucket were [CloudTrail logs][aws-cloudtrail-bucket] are stored

**Note**: these buckets should live in the `cloudtrail` account from the [Accounts configuration section](#accounts)

## CloudTrail

```ini
[cloudtrail]
log_retention_days = 90
```

- `log_retention_days`: number of days before CloudTrail logs are removed from the bucket where they are stored (this is
  used to validate the data partition configuration in [AwsAthenaDataPartition][src-partition])

## Organizational unit

```ini
[organizational_unit]
include_root_accounts = true
parent = Parent OU
```

-   `include_root_accounts`: \[true|false\] indicate whether accounts in the
    [root organizational unit][aws-organizations-root] should be included in the accounts list that tasks will be run
    against

-   `parent`: name of the parent [organizational unit][aws-organizational-ou] that will be targeted by the tasks (i.e.
    all accounts, whether they are part of this parent OU or OUs owned by this OU, will be targeted by the scanning
    tasks)

## Roles

```ini
[roles]
cloudtrail = cloudtrail_role
organizations = orgs_role
s3 = s3_role
ssm = ssm_role
username = joe.bloggs
```

- `cloudtrail`: name of the role that is assumed by this tool to perform cloudtrail-related operations
- `organizations`: name of the role that is assumed by this tool to perform organizations-related operations
- `s3`: name of the role that is assumed by this tool to perform s3-related operations
- `ssm`: name of the role that is assumed by this tool to perform ssm-related operations
- `username`: IAM user that is used to assume the above roles; can be superseded with `-u | --username` argument

## Session

```ini
[session]
duration_seconds = 3600
```

- `duration_seconds`: number of seconds during which an assumed-role session is valid

## Tasks

```ini
[tasks]
executor = 10
```

- `executor`: number of task executors that run tasks in parallel

[aws-athena]: https://docs.aws.amazon.com/athena/latest/ug/what-is.html
[aws-athena-querying]: https://docs.aws.amazon.com/athena/latest/ug/querying.html
[aws-cloudtrail]: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html
[aws-cloudtrail-bucket]: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html
[aws-organizational-ou]: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_getting-started_concepts.html#organizationalunit
[aws-organizations]: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html
[aws-organizations-root]: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_getting-started_concepts.html#root
[doc-requirements]: ./requirements.md
[src-partition]: ../src/data/aws_athena_data_partition.py
