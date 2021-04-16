ARG PYTHON_VERSION

FROM python:${PYTHON_VERSION}-alpine AS linter-base
RUN apk add --no-cache shadow~=4.8
# UID of current user who runs the build
ARG user_id
# GID of current user who runs the build
ARG group_id
# HOME of current user who runs the build
ARG home
# change GID for dialout group which collides with MacOS staff GID (20) and
# create group and user to match permmisions of current who runs the build
ARG workdir
WORKDIR ${workdir}
RUN groupmod -g 64 dialout \
    && addgroup -S \
    -g "${group_id}" \
    union \
    && groupmod -g 2999 ping \
    && mkdir -p "${home}" \
    && adduser -S \
    -u "${user_id}" \
    -h "${home}" \
    -s "/bin/bash" \
    -G union \
    builder \
    && chown -R builder:union "${workdir}"

FROM linter-base AS pipenv
RUN apk add --no-cache \
    bash=~5.1 \
    curl=~7.74 \
    gcc~=10.2 \
    libc-dev~=0.7 \
    make=~4.3 \
    && pip install pipenv==2020.11.15
USER builder
# Install Python dependencies so they are cached
ARG workdir
WORKDIR ${workdir}
COPY --chown=builder:union Pipfile Pipfile.lock ./
RUN pipenv install --ignore-pipfile --dev
ENTRYPOINT [ "/usr/local/bin/pipenv" ]
