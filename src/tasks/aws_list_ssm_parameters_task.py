from dataclasses import dataclass
from typing import Any, Dict, List

from src.clients.aws_ssm_client import AwsSSMClient
from src.data.aws_organizations_types import Account
from src.data.aws_ssm_types import Parameter, TYPES
from src.tasks.aws_ssm_task import AwsSSMTask


@dataclass
class AwsListSSMParametersTask(AwsSSMTask):
    def __init__(self, account: Account) -> None:
        super().__init__("list SSM parameters", account)

    def _run_task(self, client: AwsSSMClient) -> Dict[Any, Any]:
        parameters = client.list_parameters()
        return {
            "ssm_parameters": parameters,
            "type_count": {param_type: len(self._filter_parameters(parameters, param_type)) for param_type in TYPES},
            "total_count": len(parameters),
        }

    @staticmethod
    def _filter_parameters(parameters: List[Parameter], param_type: str) -> List[Parameter]:
        return list(filter(lambda param: param.type == param_type, parameters))
