LIST_OBJECTS_V2_PAGE_1 = {
    "IsTruncated": True,
    "Contents": [
        {"Key": "AWSLogs/030595205467/CloudTrail-Digest/1"},
        {"Key": "AWSLogs/030595205467/CloudTrail-Digest/2"},
        {"Key": "AWSLogs/030595205467/CloudTrail-Digest/3"},
    ],
    "NextContinuationToken": "token_for_page_2",
}

LIST_OBJECTS_V2_PAGE_2 = {
    "IsTruncated": True,
    "Contents": [
        {"Key": "AWSLogs/030595205467/CloudTrail-Digest/4"},
        {"Key": "AWSLogs/132732819913/CloudTrail-Digest/5"},
        {"Key": "AWSLogs/132732819913/CloudTrail-Digest/6"},
    ],
    "NextContinuationToken": "token_for_page_3",
}

LIST_OBJECTS_V2_PAGE_3 = {
    "IsTruncated": False,
    "Contents": [
        {"Key": "AWSLogs/132732819913/CloudTrail-Digest/7"},
        {"Key": "AWSLogs/260671066465/CloudTrail-Digest/8"},
    ],
}

LIST_OBJECTS_V2_ALL_OBJECTS = [
    "AWSLogs/030595205467/CloudTrail-Digest/1",
    "AWSLogs/030595205467/CloudTrail-Digest/2",
    "AWSLogs/030595205467/CloudTrail-Digest/3",
    "AWSLogs/030595205467/CloudTrail-Digest/4",
    "AWSLogs/132732819913/CloudTrail-Digest/5",
    "AWSLogs/132732819913/CloudTrail-Digest/6",
    "AWSLogs/132732819913/CloudTrail-Digest/7",
    "AWSLogs/260671066465/CloudTrail-Digest/8",
]

PAGINATE_RESULTS = [
    {"Prefix": "AWSLogs/030595205467/"},
    {"Prefix": "AWSLogs/132732819913/"},
    {"Prefix": "AWSLogs/260671066465/"},
]
