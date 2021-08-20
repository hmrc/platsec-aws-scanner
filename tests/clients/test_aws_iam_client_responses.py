from tests.test_types_generator import policy, role

GET_ROLE = {
    "Role": {
        "RoleName": "a_role",
        "Arn": "arn:aws:iam::112233445566:role/a_role",
        "AssumeRolePolicyDocument": {
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sts:AssumeRole"}]
        },
    }
}

LIST_ATTACHED_ROLE_POLICIES = {
    "AttachedPolicies": [{"PolicyName": "a_policy", "PolicyArn": "arn:aws:iam::112233445566:policy/a_policy"}]
}

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
)
