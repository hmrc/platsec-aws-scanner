#!/usr/bin/env python
from src.aws_scanner_argument_parser import AwsScannerArgumentParser
from src.aws_scanner_main import AwsScannerMain

if __name__ == "__main__":
    AwsScannerMain(AwsScannerArgumentParser().parse_cli_args())
