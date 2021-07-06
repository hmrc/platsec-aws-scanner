SCAN_SERVICE_USAGE = (
    "SELECT eventsource, eventname, errorcode, COUNT(1) AS count "
    'FROM "some_db"."account_id" '
    "WHERE eventsource LIKE '%ssm%' "
    "GROUP BY eventsource, eventname, errorcode "
    "LIMIT 100"
)
SCAN_SERVICE_USAGE_RESULTS = [
    {
        "Data": [
            {"VarCharValue": "ssm.amazonaws.com"},
            {"VarCharValue": "describe_document"},
            {"VarCharValue": "AccessDenied"},
            {"VarCharValue": "1024"},
        ]
    },
    {
        "Data": [
            {"VarCharValue": "ssm.amazonaws.com"},
            {"VarCharValue": "get_inventory"},
            {},
            {"VarCharValue": "54"},
        ]
    },
]

FIND_PRINCIPAL_BY_IP = (
    "SELECT DISTINCT useridentity.principalid "
    'FROM "some_db"."account_id" '
    "WHERE sourceipaddress = '127.0.0.1' "
    "AND useridentity.principalid not like '%boto%' "
    "AND useridentity.principalid not like '%aws%' "
    "LIMIT 100"
)
FIND_PRINCIPAL_BY_ID_RESULTS = [
    {"Data": [{"VarCharValue": "AROAXERYSMBMWZ4IG2ALK:john.doo"}]},
    {"Data": [{"VarCharValue": "AROAIJTD3R5I4HY5HH7UK:joe.bloggs"}]},
    {"Data": [{"VarCharValue": "AROAJMQQWK37FT7OHCGQY:joe.bloggs"}]},
    {"Data": [{"VarCharValue": "joe.bloggs"}]},
]

SCAN_ROLE_USAGE = (
    "SELECT eventsource, eventname, count(1) as count "
    'FROM "some_db"."account_id" '
    "WHERE useridentity.arn like '%assumed-role/RoleSomething%' "
    "GROUP by eventsource, eventname "
    "ORDER by eventsource, eventname "
    "LIMIT 100"
)
SCAN_ROLE_USAGE_RESULTS = [
    {
        "Data": [
            {"VarCharValue": "cloudformation.amazonaws.com"},
            {"VarCharValue": "DescribeChangeSet"},
            {"VarCharValue": "15"},
        ]
    },
    {"Data": [{"VarCharValue": "s3.amazonaws.com"}, {"VarCharValue": "GetBucketEncryption"}, {"VarCharValue": "12"}]},
    {
        "Data": [
            {"VarCharValue": "access-analyzer.amazonaws.com"},
            {"VarCharValue": "ListAnalyzers"},
            {"VarCharValue": "4"},
        ]
    },
    {"Data": [{"VarCharValue": "s3.amazonaws.com"}, {"VarCharValue": "ListBuckets"}, {"VarCharValue": "2"}]},
]
