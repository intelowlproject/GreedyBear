FROM python:3.9.9-buster

ENV PYTHONUNBUFFERED 1
ENV DJANGO_SETTINGS_MODULE greedybear.settings
ENV PYTHONPATH /opt/deploy/greedybear
ENV LOG_PATH /var/log/greedybear

ARG WATCHMAN=false

RUN mkdir -p ${LOG_PATH} \
    ${LOG_PATH}/django \
    ${LOG_PATH}/uwsgi

# python3-psycopg2 is required to use PostgresSQL with Django
RUN apt-get update \
    && apt-get install -y --no-install-recommends apt-utils libsasl2-dev libssl-dev \
    vim python-dev libfuzzy-dev net-tools python3-psycopg2 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --upgrade pip

COPY requirements/requirements.txt $PYTHONPATH/requirements.txt
COPY requirements/test-requirements.txt $PYTHONPATH/test-requirements.txt
WORKDIR $PYTHONPATH

RUN pip3 install --no-cache-dir --compile -r requirements.txt

COPY . $PYTHONPATH
COPY docker/wait-for-it.sh /wait-for-it.sh

RUN touch ${LOG_PATH}/django/api.log ${LOG_PATH}/django/api_errors.log \
    && touch ${LOG_PATH}/django/gui.log ${LOG_PATH}/django/gui_errors.log \
    && touch ${LOG_PATH}/django/greedybear.log ${LOG_PATH}/django/greedybear_errors.log \
    && touch ${LOG_PATH}/django/celery.log ${LOG_PATH}/django/celery_errors.log \
    && touch ${LOG_PATH}/django/django_errors.log ${LOG_PATH}/django/elasticsearch.log\
    && chown -R www-data:www-data ${LOG_PATH} /opt/deploy/

RUN docker/watchman_install.sh
