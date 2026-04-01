## ------------------------------- UV Stage ------------------------------ ## 

FROM python:3.13-slim-trixie AS uv

COPY --from=ghcr.io/astral-sh/uv:0.11.1 /uv /bin/uv
COPY pyproject.toml .  

RUN echo "VITE_GREEDYBEAR_VERSION=\"$(uv version --short)\"" > .env.local


## ------------------------------- Frontend Build Stage ------------------------------ ## 

FROM node:lts-alpine3.22 AS frontend-build

WORKDIR /app

# install dependencies first for layer caching
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

# copy source code and build
COPY frontend/ .
COPY --from=uv /.env.local .
RUN VITE_BASE_URL=/static/reactapp/ npm run build


## ------------------------------- Production Stage ------------------------------ ##

FROM uv AS production

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=greedybear.settings
ENV APP_ROOT=/opt/deploy/greedybear
ENV LOG_PATH=/var/log/greedybear
ENV UV_PROJECT_ENVIRONMENT=/usr/local

WORKDIR $APP_ROOT

# Install runtime dependencies
#  - libgomp1 is required for model training
#  - curl is used for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 curl gosu \
    && rm -rf /var/lib/apt/lists/*

# Install python packages
COPY pyproject.toml uv.lock ./
RUN uv sync --no-dev --locked

# Copy files
COPY . $APP_ROOT
COPY --from=frontend-build /app/build /var/www/reactapp

# separation is required to avoid to re-execute os installation in case of change of python requirements
RUN mkdir -p ${LOG_PATH}/django ${LOG_PATH}/gunicorn \
    && touch ${LOG_PATH}/django/api.log ${LOG_PATH}/django/api_errors.log \
    && touch ${LOG_PATH}/django/greedybear.log ${LOG_PATH}/django/greedybear_errors.log \
    && touch ${LOG_PATH}/django/django_q.log ${LOG_PATH}/django/django_q_errors.log \
    && touch ${LOG_PATH}/django/django_errors.log ${LOG_PATH}/django/elasticsearch.log \
    && touch ${LOG_PATH}/django/authentication.log ${LOG_PATH}/django/authentication_errors.log \
    && mkdir -p ${APP_ROOT}/mlmodels \
    && chown -R www-data:www-data ${LOG_PATH} /opt/deploy/ ${APP_ROOT}/mlmodels/ \
    && rm -rf frontend/


## ------------------------------- Development Stage ------------------------------ ##

FROM production AS development

# Install dev dependencies
RUN uv sync --group dev --locked


## ------------------------------- Default Stage ------------------------------ ##

# Ensure the default build target is production
FROM production
