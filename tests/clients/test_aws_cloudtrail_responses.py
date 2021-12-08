LIST_TRAILS_RESPONSE_ONE = {
    "Trails": [
        {
            "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-1",
            "Name": "test_trail_001",
            "HomeRegion": "eu-west-2",
        },
    ]
}

LIST_TRAILS_RESPONSE_TWO = {
    "Trails": [
        {
            "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-1",
            "Name": "test_trail_001",
            "HomeRegion": "eu-west-2",
        },
        {
            "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-2",
            "Name": "test_trail_002",
            "HomeRegion": "eu-west-2",
        },
    ]
}

LIST_TRAILS_RESPONSE_WITH_TOKEN = {
    "Trails": [
        {
            "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-1",
            "Name": "test_trail_001",
            "HomeRegion": "eu-west-2",
        },
        {
            "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-2",
            "Name": "test_trail_002",
            "HomeRegion": "eu-west-2",
        },
    ],
    "NextToken": "xyxyxxyy",
}
