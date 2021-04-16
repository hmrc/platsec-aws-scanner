# List organization accounts

The `list_accounts` task lists all the AWS accounts of the organization.

**Notes**:

-   every account in the root organizational unit, along with every account in the leaves organizational units for the
    entire organization tree will be listed

-   the organization tree that is walked by this task is expected to exist in the
    [AWS Organizations service][aws-organizations] for the `root` account as configured in
    [the configuration file](../configuration.md#accounts)

## Usage

```sh
./platsec_aws_scanner.sh list_accounts -u john.doo -t 123456
```

See the [common arguments section](../usage.md#common-arguments) for details on the common arguments.

## Task report

```json
[
  {
    "account": {
      "identifier": "999888777666",
      "name": "root"
    },
    "description": "list accounts in organization",
    "results": {
      "accounts": [
        {
          "identifier": "112233445566",
          "name": "some account"
        },
        {
          "identifier": "787878787878",
          "name": "some other account"
        },
        {
          "identifier": "919291929192",
          "name": "another account"
        },
        {
          "identifier": "345534553455",
          "name": "yet another account"
        }
      ]
    }
  }
]
```

See the [task report section](../usage.md#task-report) for details on the common task report fields.

- `results`:

  - `accounts`: list of accounts in the organization

[aws-organizations]: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html
