from src.csv_serializer import to_csv

from tests.test_types_generator import account, instance, task_report


reports = [
    task_report(
        account=account(identifier="1234", name="first-account"),
        description="audit_ec2_instances",
        partition=None,
        results={
            "ec2_instances": [
                instance(id="i-1", component="comp-1", image_id="ami-1"),
                instance(id="i-2", component="comp-2", image_id="ami-2"),
            ]
        },
    ),
    task_report(
        account=account(identifier="5678", name="second-account"),
        description="audit_ec2_instances",
        partition=None,
        results={
            "ec2_instances": [
                instance(id="i-3", component="comp-3", image_id="ami-3"),
                instance(id="i-4", component="comp-4", image_id="ami-4"),
            ]
        },
    ),
]

expected_csv = """account_id,account_name,instance_id,instance_component,instance_image_id,instance_image_creation_date,instance_launch_time,instance_metadata_options_http_tokens
1234,first-account,i-1,comp-1,ami-1,2020-03-23 09:01:26+00:00,2020-03-25 09:06:07+00:00,required
1234,first-account,i-2,comp-2,ami-2,2020-03-23 09:01:26+00:00,2020-03-25 09:06:07+00:00,required
5678,second-account,i-3,comp-3,ami-3,2020-03-23 09:01:26+00:00,2020-03-25 09:06:07+00:00,required
5678,second-account,i-4,comp-4,ami-4,2020-03-23 09:01:26+00:00,2020-03-25 09:06:07+00:00,required"""


def test_to_csv() -> None:
    assert to_csv(reports) == expected_csv
