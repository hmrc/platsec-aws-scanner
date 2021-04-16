SCAN_SERVICE_USAGE = (
    "SELECT eventsource, eventname, COUNT(1) AS count "
    'FROM "$database"."$account" '
    "WHERE eventsource LIKE '%$service%' "
    "GROUP BY eventsource, eventname "
    "LIMIT 100"
)

FIND_PRINCIPAL_BY_IP = (
    "SELECT DISTINCT useridentity.principalid "
    'FROM "$database"."$account" '
    "WHERE sourceipaddress = '$source_ip' "
    "AND useridentity.principalid not like '%boto%' "
    "AND useridentity.principalid not like '%aws%' "
    "LIMIT 100"
)

SCAN_ROLE_USAGE = (
    "SELECT eventsource, eventname, count(1) as count "
    'FROM "$database"."$account" '
    "WHERE useridentity.arn like '%assumed-role/$role%' "
    "GROUP by eventsource, eventname "
    "ORDER by eventsource, eventname "
    "LIMIT 100"
)
