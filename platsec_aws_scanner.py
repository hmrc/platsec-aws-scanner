#!/usr/bin/env python
import logging

from src.aws_scanner_main import AwsScannerMain

logging.basicConfig(
    level=logging.INFO,
    datefmt="%Y-%m-%dT%H:%M:%S",
    format="%(asctime)s %(levelname)s %(module)s %(message)s",
)
logging.getLogger("botocore").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)

if __name__ == "__main__":
    AwsScannerMain()
