ARG PYTHON_VERSION
FROM python:${PYTHON_VERSION}-slim-buster
RUN sed -i 's/http:/https:/g' /etc/apt/sources.list
RUN useradd --create-home scanner
USER scanner
WORKDIR /home/scanner
ARG PIP_PIPENV_VERSION
RUN pip install pipenv==${PIP_PIPENV_VERSION} --index-url https://artefacts.tax.service.gov.uk/artifactory/api/pypi/pips/simple
COPY ./Pipfile.lock ./
RUN python -m pipenv sync --pypi-mirror https://artefacts.tax.service.gov.uk/artifactory/api/pypi/pips/simple
RUN mv $(python -m pipenv --venv)/lib/python3.9/site-packages/* ./
COPY ./ ./
ARG CONFIG_FILE
RUN mv ${CONFIG_FILE} ./aws_scanner_config.ini
ENTRYPOINT ["python", "-m", "platsec_aws_scanner"]
