# Limitations

## Injection

Queries are templated and arguments are substituted without sanitizing. The reasoning behind this design choice is that
databases and tables in Athena are short-lived, throw-away resources and don't (or at least shouldn't) contain sensitive
information. Even if a database/table is damaged via query injection, the database/table can always be
recreated/partitioned because the data source of truth isn't affected as it lives in the CloudTrail logs stored in S3.

## Missing pagination

Pagination has not been implemented yet on the following resources:

- `aws_athena_async_client.AwsAthenaAsyncClient.list_databases` ([max page size 50][1])
- `aws_organizations_client.AwsOrganizationsClient._list_roots` ([max page size 20][2])
- `aws_organizations_client.AwsOrganizationsClient._list_org_units_for_parent` ([max page size 20][3])

[1]: https://docs.aws.amazon.com/athena/latest/APIReference/API_ListDatabases.html
[2]: https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListRoots.html
[3]: https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListOrganizationalUnitsForParent.html
