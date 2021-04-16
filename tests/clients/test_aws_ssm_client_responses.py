from tests.test_types_generator import secure_string_parameter, string_list_parameter, string_parameter

DESCRIBE_PARAMETERS_PAGE_1 = {
    "Parameters": [
        {"Name": "some_top_level_parameter", "Type": "String", "Version": 1},
        {"Name": "/secure/param/with/path", "Type": "SecureString", "Version": 1},
    ],
    "NextToken": "token_for_params_page_2",
}
DESCRIBE_PARAMETERS_PAGE_2 = {
    "Parameters": [
        {"Name": "/list/param/with/path", "Type": "StringList", "Version": 1},
    ]
}
EXPECTED_LIST_PARAMETERS = [
    string_parameter(name="some_top_level_parameter"),
    secure_string_parameter(name="/secure/param/with/path"),
    string_list_parameter(name="/list/param/with/path"),
]
