# Cost Usage

The `cost_explorer` task outputs data showing the usage & cost of a specified service in a given account / list of
accounts.

The service being queried needs to be specified using its full name, example:

- Amazon Api Gateway
- Amazon Cloudfront
- Amazon DynamoDB
- Amazon Simple Storage Service
- Amazon Virtual Private Cloud
- AWS CodePipeline
- AWS CodeBuild
- AWS CodeArtifact
- AWS Lambda
- AWS X-Ray

You can see a list of full names of services by clicking on the service [here](https://docs.aws.amazon.com/index.html),
then you'll see the full name on the next page, i.e "**Amazon Simple Storage Service** Documentation".

## Usage

```sh
./platsec_aws_scanner.sh cost_explorer -m 07 -y 2021 -s "AWS Lambda" -u freda.bloggs -t 123456 -a 999888777666
```

### Arguments

- -m or --month represents the month to start the search from. Must be in *n* or *nn* format, without the leading zero.
- -y or --year represents the year to start the search from. Must be in *nnnn* format.

The scanner will check for costs and usage from the 1st day of the month and year specified
in the command, ending on the current date. However, [AWS documentation](https://bit.ly/3kKZPJw) states that the end
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
