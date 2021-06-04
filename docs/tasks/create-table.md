# Create Athena databases and tables

The `create_table` task creates databases and tables in Athena and populates the tables with CloudTrail logs data as per
the partition arguments passed in.

**Notes**:

-   databases and tables are created in the `athena` account as configured in
    [the configuration file](../configuration.md#athena)

-   database names are prefixed according to the `database_prefix` value in
    [the configuration file](../configuration.md#athena)

-   database and table names contain the account identifier that they relate to

-   database names have a randomly generated suffix to prevent name clashes when tasks fail to
    [tear down](../usage.md#task-setup-and-tear-down) and other tasks are run against similar accounts

-   unlike other Athena/CloudTrail tasks, the `create_table` task doesn't execute the
    [tear down](../usage.md#task-setup-and-tear-down) process after completion so that the databases and tables that
    were created can be used for running ad-hoc queries in the AWS console or via the AWS CLI. The [drop](drop.md) task
    can be invoked to dispose of these databases and tables once they are not needed anymore.

## Usage

```sh
./platsec_aws_scanner.sh create_table -u john.doo -t 123456 -y 2021 -m 3 -a 999888777666,111222111222
```

See the [common arguments section](../usage.md#common-arguments) for details on the common arguments.

## Task report

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
      "month": "03"
    },
    "results": {
      "database": "aws_scanner_999888777666_5305763905",
      "table": "999888777666"
    }
  },
  {
    "account": {
      "identifier": "111222111222",
      "name": "some-other-account"
    },
    "description": "create Athena table and load data partition",
    "partition": {
      "year": "2021",
      "month": "03"
    },
    "results": {
      "database": "aws_scanner_111222111222_0070162439",
      "table": "111222111222"
    }
  }
]
```

See the [task report section](../usage.md#task-report) for details on the common task report fields.

- `results`:

  -   `database`: name of the database that this task has created in Athena

  -   `table`: name of the table that this task has created in Athena and loaded with CloudTrail logs data for the
      specified partition settings
