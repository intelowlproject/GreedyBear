# Stage 1: Frontend 
FROM node:lts-alpine3.14 as frontend-build

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
FROM python:3.9.16-alpine3.17

COPY --from=frontend-build /build /var/www/reactapp

ENV PYTHONUNBUFFERED 1
ENV DJANGO_SETTINGS_MODULE greedybear.settings
ENV PYTHONPATH /opt/deploy/greedybear
ENV LOG_PATH /var/log/greedybear

ARG WATCHMAN=false

RUN mkdir -p ${LOG_PATH} \
    ${LOG_PATH}/django \
    ${LOG_PATH}/uwsgi

# python3-psycopg2 is required to use PostgresSQL with Django
RUN apk --no-cache -U add util-linux libsasl libressl-dev \
    vim net-tools py3-psycopg2 bash uwsgi \
    && pip3 install --upgrade pip

COPY requirements/project-requirements.txt $PYTHONPATH/project-requirements.txt
COPY requirements/test-requirements.txt $PYTHONPATH/test-requirements.txt
WORKDIR $PYTHONPATH

RUN pip3 install --no-cache-dir --compile -r project-requirements.txt

COPY . $PYTHONPATH
COPY docker/wait-for-it.sh /wait-for-it.sh

RUN touch ${LOG_PATH}/django/api.log ${LOG_PATH}/django/api_errors.log \
    && touch ${LOG_PATH}/django/greedybear.log ${LOG_PATH}/django/greedybear_errors.log \
    && touch ${LOG_PATH}/django/celery.log ${LOG_PATH}/django/celery_errors.log \
    && touch ${LOG_PATH}/django/django_errors.log ${LOG_PATH}/django/elasticsearch.log\
    && adduser -S -H -u 2000 -D -g www-data www-data \
    && chown -R www-data:www-data ${LOG_PATH} /opt/deploy/ \
    && rm -rf docs/ frontend/ tests/ .github/

RUN /bin/bash ./docker/watchman_install.sh
