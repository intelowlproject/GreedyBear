# Stage 1: Frontend 
FROM node:lts-alpine3.22 AS frontend-build

WORKDIR /
# copy react source code
COPY frontend/ .
# copy version file as an env file
COPY docker/.version .env.local
# install and build
RUN npm install npm@latest --location=global
RUN npm install

RUN PUBLIC_URL=/static/reactapp/ npm run build

# Stage 2: Backend
FROM python:3.13-slim-trixie

ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=greedybear.settings
ENV PYTHONPATH=/opt/deploy/greedybear
ENV LOG_PATH=/var/log/greedybear

ARG WATCHMAN=false

RUN mkdir -p ${LOG_PATH}/django ${LOG_PATH}/uwsgi \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       # Build dependencies (removed after pip install)
       gcc python3-dev \
       # Runtime dependencies
       # libgomp1 is required to train the model
       libgomp1 netcat-openbsd \
    && pip3 install --no-cache-dir --upgrade pip

COPY requirements/project-requirements.txt $PYTHONPATH/project-requirements.txt
COPY requirements/dev-requirements.txt $PYTHONPATH/dev-requirements.txt
WORKDIR $PYTHONPATH
RUN pip3 install --no-cache-dir -r $PYTHONPATH/project-requirements.txt

# Conditionally install dev requirements (coverage, etc.)
ARG INSTALL_DEV=false
RUN if [ "$INSTALL_DEV" = "true" ]; then \
      pip3 install --no-cache-dir -r $PYTHONPATH/dev-requirements.txt; \
    fi

COPY . $PYTHONPATH
COPY --from=frontend-build /build /var/www/reactapp

# separation is required to avoid to re-execute os installation in case of change of python requirements
RUN touch ${LOG_PATH}/django/api.log ${LOG_PATH}/django/api_errors.log \
    && touch ${LOG_PATH}/django/greedybear.log ${LOG_PATH}/django/greedybear_errors.log \
    && touch ${LOG_PATH}/django/celery.log ${LOG_PATH}/django/celery_errors.log \
    && touch ${LOG_PATH}/django/django_errors.log ${LOG_PATH}/django/elasticsearch.log\
    && touch ${LOG_PATH}/django/authentication.log ${LOG_PATH}/django/authentication_errors.log \
    && mkdir -p ${PYTHONPATH}/mlmodels \
    && usermod -u 2000 www-data \
    && chown -R www-data:www-data ${LOG_PATH} /opt/deploy/ ${PYTHONPATH}/mlmodels/ \
    && rm -rf docs/ frontend/ tests/ .github/ docker/hooks/ \
    && /bin/bash ./docker/watchman_install.sh \
    && apt-get purge -y gcc python3-dev \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# start period is high to allow data migration for 1.4.0
HEALTHCHECK --interval=10s --timeout=2s --start-period=500s --retries=3 CMD nc -z localhost 8001 || exit 1

