# List SSM parameters

The `list_ssm_parameters` task lists all the [SSM parameters][aws-param-store] for a given account or list of accounts.

## Usage

```sh
./platsec_aws_scanner.sh list_ssm_parameters -u john.doo -t 123456 -a 999888777666
```

See the [common arguments section](../usage.md#common-arguments) for details on the common arguments.

## Task report

```json
[
  {
    "account": {
      "identifier": "999888777666",
      "name": "some account"
    },
    "description": "list SSM parameters",
    "results": {
      "ssm_parameters": [
        {
          "name": "/path/to/secret/param1",
          "type": "SecureString"
        },
        {
          "name": "/path/to/secret/param2",
          "type": "SecureString"
        },
        {
          "name": "/not/a/secret/param",
          "type": "String"
        },
        {
          "name": "/path/to/list/param",
          "type": "StringList"
        }
      ],
      "type_count": {
        "SecureString": 2,
        "StringList": 1,
        "String": 1
      },
      "total_count": 4
    }
  }
]
```

See the [task report section](../usage.md#task-report) for details on the common task report fields.

* `results`:

  * `ssm_parameters`: names and types of SSM parameters for given account
  * `type_count`: count of SSM parameters grouped by types for given account
  * `total_count`: total count of SSM parameters for given account

[aws-param-store]: https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html
