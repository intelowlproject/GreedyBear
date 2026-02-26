## ------------------------------- Frontend Build Stage ------------------------------ ## 
FROM node:lts-alpine3.22 AS frontend-build

WORKDIR /app

# install dependencies first for layer caching
COPY frontend/package*.json ./
RUN npm ci

# copy source code and build
COPY frontend/ .
COPY docker/.version .env.local
RUN VITE_BASE_URL=/static/reactapp/ npm run build


## ------------------------------- Production Stage ------------------------------ ##

FROM python:3.13-slim-trixie AS production

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=greedybear.settings
ENV PYTHONPATH=/opt/deploy/greedybear
ENV LOG_PATH=/var/log/greedybear

WORKDIR $PYTHONPATH

# Install runtime dependencies
#  - libgomp1 is required for model training
#  - netcat-openbsd for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
       libgomp1 netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Install python packages
COPY requirements/project-requirements.txt requirements/project-requirements.txt
RUN pip install --no-cache-dir --root-user-action=ignore --disable-pip-version-check -q -r requirements/project-requirements.txt

# Copy files
COPY . $PYTHONPATH
COPY --from=frontend-build /app/build /var/www/reactapp

# separation is required to avoid to re-execute os installation in case of change of python requirements
RUN mkdir -p ${LOG_PATH}/django ${LOG_PATH}/uwsgi \
    && touch ${LOG_PATH}/django/api.log ${LOG_PATH}/django/api_errors.log \
    && touch ${LOG_PATH}/django/greedybear.log ${LOG_PATH}/django/greedybear_errors.log \
    && touch ${LOG_PATH}/django/django_q.log ${LOG_PATH}/django/django_q_errors.log \
    && touch ${LOG_PATH}/django/django_errors.log ${LOG_PATH}/django/elasticsearch.log \
    && touch ${LOG_PATH}/django/authentication.log ${LOG_PATH}/django/authentication_errors.log \
    && mkdir -p ${PYTHONPATH}/mlmodels \
    && usermod -u 2000 www-data \
    && chown -R www-data:www-data ${LOG_PATH} /opt/deploy/ ${PYTHONPATH}/mlmodels/ \
    && rm -rf frontend/

## ------------------------------- Development Stage ------------------------------ ##

FROM production AS development

# Install dev requirements
RUN pip install --no-cache-dir --root-user-action=ignore --disable-pip-version-check -q -r requirements/dev-requirements.txt
