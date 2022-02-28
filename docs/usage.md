# Usage

## Command-line

PlatSec AWS Scanner is a Python command-line tool that can be invoked from an activated virtual environment:

```sh
pipenv shell
Launching subshell in virtual environment...

$ ./platsec_aws_scanner.py
usage: platsec_aws_scanner.py [-h] {audit_cloudtrail,audit_central_logging,service_usage,role_usage,find_principal,list_accounts,create_table,drop} ...
```

Alternatively, an executable shell script wraps the Python script in a container for convenience:

```sh
./platsec_aws_scanner.sh
usage: platsec_aws_scanner.py [-h] {audit_cloudtrail,audit_central_logging,service_usage,role_usage,find_principal,list_accounts,create_table,drop} ...
```

## Tasks

See [Tasks](tasks) for details on the tasks that are available, what they do and how to use them.

### Common arguments

Each task that performs Athena queries on CloudTrail data has a set of common arguments:

```sh
./platsec_aws_scanner.sh create_table --username john.doo --token 123456 --year 2021 --month 3 --accounts 888777666555
```

Arguments also have abbreviations:

```sh
./platsec_aws_scanner.sh create_table -u john.doo -t 123456 -y 2021 -m 3 -a 888777666555
```

-   `-u / --username` (optional): actions performed by the tool will be under this username's identity (the related AWS
    IAM user is required to exist in the [user account](configuration.md#user)); supersedes `name` in [the
    configuration file](configuration.md#user) when present

-   `-t / --token` (required): MFA token for the above user

-   `-y / --year` (optional): year for partitioning data in Athena (current year if unspecified)

-   `-m / --month` (optional): month for partitioning data in Athena (current month if unspecified)

-   `-d / --day` (optional): day for partitioning data in Athena

-   `-re / --region` (optional): AWS region for partitioning the CloudTrail data in Athena; supersedes `region` in [the
    configuration file](configuration.md#cloudtrail) when present

-   `-a / --accounts` (optional): comma-separated list of accounts to be targeted by the task being run (when omitted,
    the task will be run against all accounts that live in and under the [parent organizational unit specified in the
    configuration file](configuration.md#organization))

-   `-p / --parent` (optional): organization unit parent to be targeted by the task being run (when omitted, the task
    will be run against all accounts that live in and under the [parent organizational unit specified in the
    configuration file](configuration.md#organization))

-   `-v / --verbosity` (optional): log level configuration; one of \["error" (default), "warning", "info", "debug"\]

### Task report

Tasks are executed [in parallel](configuration.md#tasks). Each successful task produces a report. Once all tasks have
completed, an aggregate of all the reports is printed in the terminal. It's also possible to pipe the report into
another program like `jq` for pretty printing/filtering, or redirect the report to a file.

```json
[
  {
    "account": {
      "identifier": "999888777666",
      "name": "some-account"
    },
    "description": "create Athena table and load data partition",
    "partition": {
      "year": "2021",
      "month": "03",
      "region": "eu-west-1"
    },
    "results": {
      "database": "aws_scanner_999888777666_5305763905",
      "table": "999888777666"
    }
  }
]
```

- `account`: the AWS account that the task was run against
- `description`: reminds which task type was run
- `partition`: the CloudTrail logs data partition that was loaded for this account in Athena
- `results`: the task outcome

### Task setup and tear down

Tasks that run Athena queries against CloudTrail logs data have:

-   an automatic setup process to create the required databases and tables; this setup triggers before queries are run

-   an automatic tear down process to drop databases and tables that were created as part of the setup; this tear down
    triggers once the queries have completed

> Tear down is run on a best effort basis and may fail for tasks that hit AWS Athena query rate limits when
> running; this is because dropping databases and tables also are queries behind the scenes. Tasks leftovers that
> failed to be torn down can be cleaned-up with the [drop task](tasks/drop.md).

## Helper messages

Invoking the tool with the `-h / --help` argument will print a helper message listing the different tasks available:

```sh
./platsec_aws_scanner.sh -h
usage: platsec_aws_scanner.py [-h] {audit_cloudtrail,audit_central_logging,service_usage,role_usage,find_principal,list_accounts,list_ssm_parameters,create_table,drop,audit_s3} ...

positional arguments:
  {audit_cloudtrail,audit_central_logging,service_usage,role_usage,find_principal,list_accounts,list_ssm_parameters,create_table,drop,audit_s3}
    audit_cloudtrail      audit cloudtrail compliance
    audit_central_logging audit central logging account
    service_usage         scan AWS service usage 
    role_usage            scan AWS role usage
    find_principal        find principal by source IP
    list_accounts         list organization accounts
    list_ssm_parameters   list SSM parameters
    create_table          create Athena table
    drop                  drop databases and tables created by tasks
    audit_s3              audit S3 bucket compliance

optional arguments:
  -h, --help            show this help message and exit
```

It's also possible to print a helper message on a specific task with the `-h / --help` argument:

```sh
./platsec_aws_scanner.sh service_usage -h
usage: platsec_aws_scanner.py service_usage [-h] [-u USERNAME] -t TOKEN -y YEAR -m MONTH [-re REGION] [-a ACCOUNTS] -s SERVICES [-v {error,warning,info,debug}]

scan AWS service usage

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        username that assumes AWS roles
  -t TOKEN, --token TOKEN
                        AWS mfa token
  -y YEAR, --year YEAR  year for AWS Athena data partition
  -m MONTH, --month MONTH
                        month for AWS Athena data partition
  -re REGION, --region REGION
                        region for AWS Athena data partition
  -a ACCOUNTS, --accounts ACCOUNTS
                        comma-separated list of target accounts
  -p PARENT, --parent PARENT
                        organization unit parent
  -s SERVICES, --services SERVICES
                        comma-separated list of service(s) to scan usage for
  -v {error,warning,info,debug}, --verbosity {error,warning,info,debug}
                        log level configuration
```
