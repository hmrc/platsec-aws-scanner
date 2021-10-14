from typing import Sequence

from src.data.aws_common_types import Tag


PLATSEC_SCANNER_TAGS: Sequence[Tag] = [
    Tag(key="allow-management-by-platsec-scanner", value="true"),
    Tag(key="src-repo", value="https://github.com/hmrc/platsec-aws-scanner"),
]
