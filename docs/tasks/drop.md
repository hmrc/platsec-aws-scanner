# Drop Athena databases and tables

The `drop` task drops Athena databases and tables that were created by previously run tasks.

**Notes**:

-   the `drop` task only drops Athena databases whose names start with the `database_prefix` as configured in
    [the configuration file](../configuration.md#athena)

-   the Athena databases and tables are expected to live in the `cloudtrail` account as configured in
    [the configuration file](../configuration.md#accounts)

## Usage

```sh
./platsec_aws_scanner.sh drop -u john.doo -t 123456
```

See the [common arguments section](../usage.md#common-arguments) for details on the common arguments.

## Task report

```json
[
  {
    "account": {
      "identifier": "555666777888",
      "name": "cloudtrail"
    },
    "description": "clean scanner leftovers",
    "results": {
      "dropped_tables": [
        "aws_scanner_887788778877_5305763905.887788778877",
        "aws_scanner_123123123123_0070162439.123123123123",
        "aws_scanner_444555666777_8187033619.444555666777"
      ],
      "dropped_databases": [
        "aws_scanner_887788778877_5305763905",
        "aws_scanner_123123123123_0070162439",
        "aws_scanner_444555666777_8187033619"
      ]
    }
  }
]
```

See the [task report section](../usage.md#task-report) for details on the common task report fields.

- `results`:

  - `dropped_tables`: fully qualified names of the Athena tables that were dropped by the task (in the form of `database_name.table_name`)
  - `dropped_databases`: names of the Athena databases that were dropped by the task
