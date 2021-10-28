from tests.test_types_generator import role, policy, tag

GET_ROLE = {
    "Role": {
        "RoleName": "a_role",
        "Arn": "arn:aws:iam::112233445566:role/a_role",
        "AssumeRolePolicyDocument": {
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sts:AssumeRole"}]
        },
        "Tags": [{"Key": "a_tag", "Value": "a value"}, {"Key": "some_tag", "Value": "some value"}],
    }
}

ROLE_WITH_NO_TAGS = {
    "RoleName": "another_role",
    "Arn": "arn:aws:iam::888777666555:role/another_role",
    "AssumeRolePolicyDocument": {
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "logs.amazonaws.com"}, "Action": "sts:AssumeRole"}]
    },
}

LIST_ATTACHED_ROLE_POLICIES_PAGES = [
    {"AttachedPolicies": [{"PolicyName": "a_policy", "PolicyArn": "arn:aws:iam::112233445566:policy/a_policy"}]}
]

GET_POLICY = {
    "Policy": {"PolicyName": "a_policy", "Arn": "arn:aws:iam::112233445566:policy/a_policy", "DefaultVersionId": "v3"}
}

GET_POLICY_VERSION = {
    "PolicyVersion": {
        "Document": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:PutLogEvents",
                        "logs:DescribeLogStreams",
                        "logs:DescribeLogGroups",
                        "logs:CreateLogStream",
                    ],
                    "Resource": "*",
                }
            ],
        }
    }
}

EXPECTED_ROLE = role(
    name="a_role",
    arn="arn:aws:iam::112233445566:role/a_role",
    assume_policy={
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sts:AssumeRole"}]
    },
    policies=[
        policy(
            name="a_policy",
            arn="arn:aws:iam::112233445566:policy/a_policy",
            default_version="v3",
            document={
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:PutLogEvents",
                            "logs:DescribeLogStreams",
                            "logs:DescribeLogGroups",
                            "logs:CreateLogStream",
                        ],
                        "Resource": "*",
                    }
                ]
            },
        )
    ],
    tags=[tag("a_tag", "a value"), tag("some_tag", "some value")],
)

EXPECTED_ROLE_WITH_NO_TAGS = role(
    name="another_role",
    arn="arn:aws:iam::888777666555:role/another_role",
    assume_policy={
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "logs.amazonaws.com"}, "Action": "sts:AssumeRole"}]
    },
    policies=[],
    tags=[],
)

LIST_ENTITIES_FOR_POLICY = {"PolicyRoles": [{"RoleName": "a_role"}, {"RoleName": "another_role"}]}

LIST_POLICY_VERSIONS = {
    "Versions": [
        {"VersionId": "v3", "IsDefaultVersion": True},
        {"VersionId": "v2", "IsDefaultVersion": False},
        {"VersionId": "v1", "IsDefaultVersion": False},
    ]
}

LIST_POLICIES_PAGES = [
    {
        "Policies": [
            {"PolicyName": "pol_1", "Arn": "pol_1_arn"},
            {"PolicyName": "pol_2", "Arn": "pol_2_arn"},
            {"PolicyName": "pol_3", "Arn": "pol_3_arn"},
        ]
    },
    {
        "Policies": [
            {"PolicyName": "pol_4", "Arn": "pol_4_arn"},
            {"PolicyName": "pol_5", "Arn": "pol_5_arn"},
        ]
    },
]
