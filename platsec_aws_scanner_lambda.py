from src.aws_scanner_argument_parser import AwsScannerArgumentParser
from src.aws_scanner_main import AwsScannerMain


def handler(event, context):
    AwsScannerMain(AwsScannerArgumentParser().parse_lambda_args(event))
