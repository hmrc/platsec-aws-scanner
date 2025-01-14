# Cost Usage

The `cost_explorer` task outputs data showing the usage & cost
of services in a given region and account / list of accounts
for the last 12 months.

## Usage

```sh
./platsec_aws_scanner.sh cost_explorer -u freda.bloggs -t 123456 -a 999888777666
```

### Arguments

* None

The scanner will check for costs and usage from the 1st day of the month one year ago
in the command, ending on the current date. However, [AWS Cost Explorer documentation][aws-cost-explorer] states that
the end
date is exclusive, meaning that AWS will check cost usage up to the date *proceeding* the requested end date.

See the [common arguments section](../usage.md#common-arguments) for details on the common arguments.

## Response

```json
[{
	"account": {
		"identifier": "123456789012",
		"name": "Account Name"
	},
	"description": "cost & usage of AWS Lambda",
	"results": {
		"service": "AWS Lambda",
		"dateRange": {
			"start": "2021-07-01",
			"end": "2021-09-24"
		},
		"totalCost:": "USD 513",
		"totalUsage": "41485454"
	}
}]
```

[aws-cost-explorer]: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ce.html#CostExplorer
