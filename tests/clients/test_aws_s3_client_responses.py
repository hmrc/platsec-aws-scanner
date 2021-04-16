from tests.test_types_generator import bucket

LIST_BUCKETS = {
    "Buckets": [
        {"Name": "a-bucket", "CreationDate": "2015, 1, 1"},
        {"Name": "another-bucket", "CreationDate": "2015, 1, 1"},
    ],
    "Owner": {"DisplayName": "string", "ID": "string"},
}
EXPECTED_LIST_BUCKETS = [bucket("a-bucket"), bucket("another-bucket")]
