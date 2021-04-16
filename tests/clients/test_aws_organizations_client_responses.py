# type: ignore
from tests.test_types_generator import account, organizational_unit

ROOTS = {
    "Roots": [
        {
            "Id": "r-root1",
            "Name": "Root 1",
        }
    ]
}
ORG_UNITS_FOR_ROOT = {
    "OrganizationalUnits": [
        {
            "Id": "ou-root1-1",
            "Name": "Root 1 > Org Unit 1",
        },
        {
            "Id": "ou-root1-2",
            "Name": "Root 1 > Org Unit 2",
        },
    ]
}
ORG_UNITS_FOR_ORG_UNIT_2 = {
    "OrganizationalUnits": [
        {
            "Id": "ou-root1-2-1",
            "Name": "Root 1 > Org Unit 2 > Org Unit 1",
        },
        {
            "Id": "ou-root1-2-2",
            "Name": "Root 1 > Org Unit 2 > Org Unit 2",
        },
    ]
}
EMPTY_ORG_UNITS = {"OrganizationalUnits": []}
ACCOUNTS_FOR_ROOT_1 = {
    "Accounts": [
        {
            "Id": "987654655432",
            "Name": "Root 1 > Account 1",
        }
    ]
}
ACCOUNTS_FOR_ORG_UNIT_1_PAGE_1 = {
    "Accounts": [
        {
            "Id": "987651321565",
            "Name": "Root 1 > Org Unit 1 > Account 1",
        },
        {
            "Id": "643758194672",
            "Name": "Root 1 > Org Unit 1 > Account 2",
        },
    ],
    "NextToken": "root-1-org-unit-1-next-token",
}
ACCOUNTS_FOR_ORG_UNIT_1_PAGE_2 = {
    "Accounts": [
        {
            "Id": "594678488453",
            "Name": "Root 1 > Org Unit 1 > Account 3",
        }
    ]
}
ACCOUNTS_FOR_ORG_UNIT_2 = {
    "Accounts": [
        {
            "Id": "427367948155",
            "Name": "Root 1 > Org Unit 2 > Account 1",
        },
        {
            "Id": "466181875572",
            "Name": "Root 1 > Org Unit 2 > Account 2",
        },
    ]
}
ACCOUNTS_FOR_ORG_UNIT_2_2 = {
    "Accounts": [
        {
            "Id": "346494848456",
            "Name": "Root 1 > Org Unit 2 > Org Unit 2 > Account 1",
        },
        {
            "Id": "242243167582",
            "Name": "Root 1 > Org Unit 2 > Org Unit 2 > Account 2",
        },
    ]
}
EMPTY_ACCOUNTS = {"Accounts": []}
EXPECTED_ORGANIZATION_TREE = [
    organizational_unit(
        identifier="r-root1",
        name="Root 1",
        root=True,
        accounts=[account(identifier="987654655432", name="Root 1 > Account 1")],
        org_units=[
            organizational_unit(
                identifier="ou-root1-1",
                name="Root 1 > Org Unit 1",
                accounts=[
                    account(identifier="987651321565", name="Root 1 > Org Unit 1 > Account 1"),
                    account(identifier="643758194672", name="Root 1 > Org Unit 1 > Account 2"),
                    account(identifier="594678488453", name="Root 1 > Org Unit 1 > Account 3"),
                ],
                org_units=[],
            ),
            organizational_unit(
                identifier="ou-root1-2",
                name="Root 1 > Org Unit 2",
                accounts=[
                    account(identifier="427367948155", name="Root 1 > Org Unit 2 > Account 1"),
                    account(identifier="466181875572", name="Root 1 > Org Unit 2 > Account 2"),
                ],
                org_units=[
                    organizational_unit(
                        identifier="ou-root1-2-1", name="Root 1 > Org Unit 2 > Org Unit 1", accounts=[], org_units=[]
                    ),
                    organizational_unit(
                        identifier="ou-root1-2-2",
                        name="Root 1 > Org Unit 2 > Org Unit 2",
                        accounts=[
                            account(identifier="346494848456", name="Root 1 > Org Unit 2 > Org Unit 2 > Account 1"),
                            account(identifier="242243167582", name="Root 1 > Org Unit 2 > Org Unit 2 > Account 2"),
                        ],
                        org_units=[],
                    ),
                ],
            ),
        ],
    )
]
EXPECTED_ALL_ACCOUNTS = [
    account(identifier="987651321565", name="Root 1 > Org Unit 1 > Account 1"),
    account(identifier="643758194672", name="Root 1 > Org Unit 1 > Account 2"),
    account(identifier="594678488453", name="Root 1 > Org Unit 1 > Account 3"),
    account(identifier="346494848456", name="Root 1 > Org Unit 2 > Org Unit 2 > Account 1"),
    account(identifier="242243167582", name="Root 1 > Org Unit 2 > Org Unit 2 > Account 2"),
    account(identifier="427367948155", name="Root 1 > Org Unit 2 > Account 1"),
    account(identifier="466181875572", name="Root 1 > Org Unit 2 > Account 2"),
    account(identifier="987654655432", name="Root 1 > Account 1"),
]
DESCRIBE_ACCOUNT = {
    "Account": {
        "Id": "123456789012",
        "Name": "some test account",
    }
}
EXPECTED_TARGET_ACCOUNTS = [
    account(identifier="346494848456", name="Root 1 > Org Unit 2 > Org Unit 2 > Account 1"),
    account(identifier="242243167582", name="Root 1 > Org Unit 2 > Org Unit 2 > Account 2"),
    account(identifier="427367948155", name="Root 1 > Org Unit 2 > Account 1"),
    account(identifier="466181875572", name="Root 1 > Org Unit 2 > Account 2"),
    account(identifier="987654655432", name="Root 1 > Account 1"),
]
EXPECTED_TARGET_ACCOUNTS_WITHOUT_ROOT = [
    account(identifier="346494848456", name="Root 1 > Org Unit 2 > Org Unit 2 > Account 1"),
    account(identifier="242243167582", name="Root 1 > Org Unit 2 > Org Unit 2 > Account 2"),
    account(identifier="427367948155", name="Root 1 > Org Unit 2 > Account 1"),
    account(identifier="466181875572", name="Root 1 > Org Unit 2 > Account 2"),
]
