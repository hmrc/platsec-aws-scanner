# Find principal by source IP

The `find_principal` task scans CloudTrail logs for events whose source IP matches the specified IP address and reports
on which principal this IP address belongs to.

## Usage

```sh
./platsec_aws_scanner.sh find_principal -u john.doo -t 123456 -y 2021 -m 3 -a 887766554433,545454545454 --ip 111.222.111.222
```

See the [common arguments section](../usage.md#common-arguments) for details on the common arguments.

- `-i / --ip`: IP address of the principal to be found

## Task report

```json
[
  {
    "account": {
      "identifier": "887766554433",
      "name": "some account"
    },
    "description": "principals for source IP 111.222.111.222",
    "partition": {
      "year": "2021",
      "month": "03"
    },
    "results": {
      "principals": []
    }
  },
  {
    "account": {
      "identifier": "545454545454",
      "name": "some other account"
    },
    "description": "principals for source IP 111.222.111.222",
    "partition": {
      "year": "2021",
      "month": "03"
    },
    "results": {
      "principals": [
        "joe.bloggs"
      ]
    }
  }
]
```

See the [task report section](../usage.md#task-report) for details on the common task report fields.

- `results`:

  - `principals`: list of principals whose IP address matches the specified source IP
