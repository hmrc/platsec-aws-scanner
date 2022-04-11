from unittest.mock import Mock

from tests.test_types_generator import audit_ec2_instances_task, instance


def test_audit_ec2_instances_task() -> None:
    instances = [instance(id="1234"), instance(id="5678")]
    ec2_client = Mock(list_instances=Mock(return_value=instances))
    assert audit_ec2_instances_task()._run_task(ec2_client) == {"ec2_instances": instances}

def test_audit_ec2_instances_missing_component_task() -> None:
    instances = [instance(id="4321", component=""), instance(id="5678")]
    ec2_client = Mock(list_instances=Mock(return_value=instances))
    assert audit_ec2_instances_task()._run_task(ec2_client) == {"ec2_instances": instances}