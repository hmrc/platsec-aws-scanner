from dataclasses import dataclass
from typing import Any, Dict, Optional

from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.data.aws_organizations_types import Account


@dataclass
class AwsTaskReport:
    account: Account
    region: str
    description: str
    partition: Optional[AwsAthenaDataPartition]
    results: Dict[Any, Any]
