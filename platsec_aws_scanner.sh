#!/usr/bin/env bash
set -euo pipefail

PYTHON_VERSION=$(head -1 .python-version)
PIP_PIPENV_VERSION=$(head -1 .pipenv-version)
CONFIG_FILE="_temp_config.ini"
IMAGE_TAG="platsec_aws_scanner:local"

if [[ "$(uname)" == "Darwin" ]]; then
  cp "$(greadlink -f aws_scanner_config.ini)" "$CONFIG_FILE"
else
  cp "$(readlink -f aws_scanner_config.ini)" "$CONFIG_FILE"
fi

docker build \
  --tag "$IMAGE_TAG" \
  --build-arg PYTHON_VERSION="$PYTHON_VERSION" \
  --build-arg PIP_PIPENV_VERSION="$PIP_PIPENV_VERSION" \
  --build-arg CONFIG_FILE="$CONFIG_FILE" \
  -f local.Dockerfile \
  . \

rm -f "$CONFIG_FILE"

docker run \
  --rm \
  -v "$HOME"/.aws/:/home/scanner/.aws/ \
  --env AWS_DEFAULT_REGION \
  --env AWS_REGION \
  --env AWS_ACCESS_KEY_ID \
  --env AWS_SECRET_ACCESS_KEY \
  --env AWS_SESSION_TOKEN \
  --env AWS_SECURITY_TOKEN \
  "$IMAGE_TAG" "$@"
