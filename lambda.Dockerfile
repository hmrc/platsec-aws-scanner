ARG PYTHON_VERSION
ARG FUNCTION_DIR="/platsec-aws-scanner"

FROM python:${PYTHON_VERSION}-slim as build-image
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
    && apt-get install -y \
    g++ \
    make \
    cmake \
    unzip \
    libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*
ARG FUNCTION_DIR
WORKDIR ${FUNCTION_DIR}
ARG PIP_PIPENV_VERSION
RUN pip install --no-cache-dir pipenv==${PIP_PIPENV_VERSION}
RUN pip install --no-cache-dir --target ${FUNCTION_DIR} awslambdaric==1.2.0
COPY Pipfile.lock ${FUNCTION_DIR}
RUN PIPENV_VENV_IN_PROJECT=1 pipenv sync

FROM python:${PYTHON_VERSION}-slim as dev
COPY --from=build-image . .
ARG FUNCTION_DIR
WORKDIR ${FUNCTION_DIR}
COPY . .
RUN PIPENV_VENV_IN_PROJECT=1 pipenv sync --dev

FROM python:${PYTHON_VERSION}-slim as production
ARG FUNCTION_DIR
WORKDIR ${FUNCTION_DIR}
COPY --from=build-image ${FUNCTION_DIR} ${FUNCTION_DIR}
RUN mv ${FUNCTION_DIR}/.venv/lib/python3.9/site-packages/* ${FUNCTION_DIR}
COPY src ${FUNCTION_DIR}/src
COPY platsec_aws_scanner_lambda.py ${FUNCTION_DIR}
RUN useradd scanner
USER scanner
ENTRYPOINT [ "/usr/local/bin/python", "-m", "awslambdaric" ]
CMD ["platsec_aws_scanner_lambda.handler"]
