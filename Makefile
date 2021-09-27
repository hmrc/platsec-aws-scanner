DOCKER = docker run \
	--interactive \
	--rm \
	--env "PYTHONWARNINGS=ignore:ResourceWarning" \
	--volume "$(PWD):${PWD}:z" \
	--workdir "${PWD}"
PYTHON_COVERAGE_OMIT = "tests/*,*__init__*,*.local/*"
PYTHON_COVERAGE_FAIL_UNDER_PERCENT = 100
PYTHON_TEST_PATTERN ?= "test_*.py"
PYTHON_VERSION = $(shell head -1 .python-version)
PIP_PIPENV_VERSION = $(shell head -1 .pipenv-version)
SHELL := /bin/bash
.PHONY: $(MAKECMDGOALS)

build: pipenv

pipenv:
	@docker build \
		--tag $@ \
		--build-arg PYTHON_VERSION=$(PYTHON_VERSION) \
		--build-arg PIP_PIPENV_VERSION=$(PIP_PIPENV_VERSION) \
		--build-arg "user_id=$(shell id -u)" \
		--build-arg "group_id=$(shell id -g)" \
		--build-arg "home=${HOME}" \
		--build-arg "workdir=${PWD}" \
		--target $@ . \

fmt: pipenv
	@$(DOCKER) pipenv run black --line-length=120 .

fmt-check: pipenv
	@$(DOCKER) pipenv run black --line-length=120 --check .

static-check: pipenv
	@$(DOCKER) pipenv run flake8 --max-line-length=120 --max-complexity=10
	@$(DOCKER) pipenv run mypy --show-error-codes --namespace-packages --strict ./**/*/*.py

all-checks: python-test python-coverage fmt-check static-check md-check clean-up

python-test: pipenv
	@$(DOCKER) pipenv run coverage run \
		--append \
		--branch \
		--omit $(PYTHON_COVERAGE_OMIT) \
		--module unittest \
			discover \
			--verbose \
			--start-directory "tests/" \
			--pattern $(PYTHON_TEST_PATTERN)

python-coverage:
	@$(DOCKER) pipenv run coverage xml --omit $(PYTHON_COVERAGE_OMIT)
	@$(DOCKER) pipenv run coverage report -m --omit $(PYTHON_COVERAGE_OMIT) --fail-under $(PYTHON_COVERAGE_FAIL_UNDER_PERCENT)

md-check:
	@docker pull zemanlx/remark-lint:0.2.0
	@docker run --rm -i -v $(PWD):/lint/input:ro zemanlx/remark-lint:0.2.0 --frail .

build-lambda-image:
	@docker build \
		--file lambda.Dockerfile \
		--tag platsec_aws_scanner_lambda:lambda . \
		--build-arg PYTHON_VERSION=$(PYTHON_VERSION) \
		--build-arg PIP_PIPENV_VERSION=$(PIP_PIPENV_VERSION) \
		>/dev/null

push-lambda-image: build-lambda-image
	@aws --profile $(ROLE) ecr get-login-password | docker login --username AWS --password-stdin $(ECR)
	@docker tag  platsec_aws_scanner_lambda:lambda $(ECR)/platsec-aws-scanner:latest
	@docker push $(ECR)/platsec-aws-scanner:latest

clean-up:
	@rm -f .coverage
	@rm -f coverage.xml
