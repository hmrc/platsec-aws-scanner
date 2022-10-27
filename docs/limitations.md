# Limitations

## Injection

Queries are templated and arguments are substituted without sanitizing. The reasoning behind this design choice is that
databases and tables in Athena are short-lived, throw-away resources and don't (or at least shouldn't) contain sensitive
information. Even if a database/table is damaged via query injection, the database/table can always be
recreated/partitioned because the data source of truth isn't affected as it lives in the CloudTrail logs stored in S3.

## Missing pagination

Pagination has not been implemented on all resources. 
This is wheen there is a very low likelihood of hitting these limits in our usecases.
