# Stage 1: Frontend 
FROM node:lts-alpine3.21 AS frontend-build

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
FROM python:3.13-alpine3.21

ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=greedybear.settings
ENV PYTHONPATH=/opt/deploy/greedybear
ENV LOG_PATH=/var/log/greedybear

ARG WATCHMAN=false

RUN mkdir -p ${LOG_PATH} \
    ${LOG_PATH}/django \
    ${LOG_PATH}/uwsgi \
    # py3-psycopg2 is required to use PostgresSQL with Django \
    # libgomp is required to train the model
    && apk --no-cache -U add bash py3-psycopg2 gcc python3-dev alpine-sdk linux-headers libgomp \
    && pip3 install --no-cache-dir --upgrade pip

COPY requirements/project-requirements.txt $PYTHONPATH/project-requirements.txt
WORKDIR $PYTHONPATH
RUN pip3 install --no-cache-dir -r $PYTHONPATH/project-requirements.txt

COPY . $PYTHONPATH
COPY --from=frontend-build /build /var/www/reactapp

# separation is required to avoid to re-execute os installation in case of change of python requirements
RUN touch ${LOG_PATH}/django/api.log ${LOG_PATH}/django/api_errors.log \
    && touch ${LOG_PATH}/django/greedybear.log ${LOG_PATH}/django/greedybear_errors.log \
    && touch ${LOG_PATH}/django/celery.log ${LOG_PATH}/django/celery_errors.log \
    && touch ${LOG_PATH}/django/django_errors.log ${LOG_PATH}/django/elasticsearch.log\
    && touch ${LOG_PATH}/django/authentication.log ${LOG_PATH}/django/authentication_errors.log \
    && mkdir -p ${PYTHONPATH}/mlmodels \
    && adduser -S -H -u 2000 -D -g www-data www-data \
    && chown -R www-data:www-data ${LOG_PATH} /opt/deploy/ ${PYTHONPATH}/mlmodels/ \
    && rm -rf docs/ frontend/ tests/ .github/ docker/hooks/ \
    && /bin/bash ./docker/watchman_install.sh \
    && apk del gcc python3-dev alpine-sdk linux-headers

# start period is high to allow data migration for 1.4.0
HEALTHCHECK --interval=10s --timeout=2s --start-period=500s --retries=3 CMD nc -z localhost 8001 || exit 1

