PYTHON_VERSION = $(shell head -1 .python-version)
PIP_PIPENV_VERSION = $(shell head -1 .pipenv-version)

ifdef CI_MODE
    DOCKER = docker build \
		--target dev \
		--file lambda.Dockerfile \
		--tag test-run:local . \
		--build-arg PYTHON_VERSION=$(PYTHON_VERSION) \
		--build-arg PIP_PIPENV_VERSION=$(PIP_PIPENV_VERSION) \
		&& docker run test-run:local
else
	DOCKER = docker run \
		--interactive \
		--rm \
		--env "PYTHONWARNINGS=ignore:ResourceWarning" \
		--volume "$(PWD):${PWD}:z" \
		--workdir "${PWD}"
endif

PYTHON_COVERAGE_OMIT = "tests/*,*__init__*,*.local/*"
PYTHON_COVERAGE_FAIL_UNDER_PERCENT = 100
PYTHON_TEST_PATTERN ?= "test_*.py"
GROUP_ID ?= $(shell id -g)
USER_ID ?= $(shell id -u)
SHELL := /bin/bash
.PHONY: $(MAKECMDGOALS)

build: pipenv

pipenv:
	@docker build \
		--tag $@ \
		--build-arg PYTHON_VERSION=$(PYTHON_VERSION) \
		--build-arg PIP_PIPENV_VERSION=$(PIP_PIPENV_VERSION) \
		--build-arg "user_id=${USER_ID}" \
		--build-arg "group_id=${GROUP_ID}" \
		--build-arg "home=${HOME}" \
		--build-arg "workdir=${PWD}" \
		--target $@ . \

fmt: pipenv
	@$(DOCKER) pipenv run black --line-length=120 .

fmt-check: pipenv
	@$(DOCKER) pipenv run black --line-length=120 --check src tests

static-check: pipenv
	@$(DOCKER) pipenv run flake8 --max-line-length=120 --max-complexity=10 src tests
	@$(DOCKER) pipenv run mypy --show-error-codes --namespace-packages --strict src tests

all-checks: python-test fmt-check static-check md-check clean-up

test: all-checks

python-test: pipenv
	$(DOCKER) pipenv run pytest \
		--cov=src \
		--cov-fail-under=100 \
		--no-cov-on-fail \
		--cov-report "term-missing:skip-covered" \
		--no-header \
		tests

md-check:
	@docker pull zemanlx/remark-lint:0.2.0
	@docker run --rm -i -v $(PWD):/lint/input:ro zemanlx/remark-lint:0.2.0 --frail .

container-release:
	docker build \
		--file lambda.Dockerfile \
		--tag container-release:local . \
		--build-arg PYTHON_VERSION=$(PYTHON_VERSION) \
		--build-arg PIP_PIPENV_VERSION=$(PIP_PIPENV_VERSION)

clean-up:
	@rm -f .coverage
	@rm -f coverage.xml
