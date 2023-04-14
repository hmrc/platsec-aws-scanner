PYTHON_VERSION = $(shell head -1 .python-version)
PIP_PIPENV_VERSION = $(shell head -1 .pipenv-version)

ifdef CI_MODE
	DOCKER = $(info building dockerfile 'lambda.Dockerfile') \
		docker build \
		--target dev \
		--file lambda.Dockerfile \
		--tag test-run:ci . \
		--build-arg PYTHON_VERSION=$(PYTHON_VERSION) \
		--build-arg PIP_PIPENV_VERSION=$(PIP_PIPENV_VERSION) \
		&& docker run test-run:ci
else
	DOCKER = $(info building dockerfile 'Dockerfile') \
		docker build \
		--file Dockerfile \
                --build-arg PYTHON_VERSION=$(PYTHON_VERSION) \
                --build-arg PIP_PIPENV_VERSION=$(PIP_PIPENV_VERSION) \
                --build-arg "user_id=${USER_ID}" \
                --build-arg "group_id=${GROUP_ID}" \
                --build-arg "home=${HOME}" \
                --build-arg "workdir=${PWD}" \
		--tag test-run:local . \
		&& docker run \
		--interactive \
		--rm \
		--env "PYTHONWARNINGS=ignore:ResourceWarning" \
		--volume "$(PWD):${PWD}:z" \
		--workdir "${PWD}" \
		test-run:local
endif

PYTHON_COVERAGE_FAIL_UNDER_PERCENT = 100
GROUP_ID ?= $(shell id -g)
USER_ID ?= $(shell id -u)
SHELL := /bin/bash
.PHONY: $(MAKECMDGOALS)

fmt:
	@$(DOCKER) pipenv run black --line-length=120 .

fmt-check:
	@$(DOCKER) pipenv run black --line-length=120 --check src tests

static-check:
	@$(DOCKER) pipenv run flake8 --max-line-length=120 --max-complexity=10 src tests
	@$(DOCKER) pipenv run mypy --show-error-codes --namespace-packages --strict src tests

all-checks: python-test fmt-check static-check md-check

test: all-checks

python-test:
	$(DOCKER) pipenv run pytest \
		--cov=src \
		--cov-fail-under=100 \
		--no-cov-on-fail \
		--cov-report "term-missing:skip-covered" \
		--no-header \
		-vvv \
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

push-lambda-image: container-release
	@aws --profile $(ROLE) ecr get-login-password | docker login --username AWS --password-stdin $(ECR)
	@docker tag container-release:local $(ECR)/platsec-aws-scanner:latest
	@docker push $(ECR)/platsec-aws-scanner:latest
