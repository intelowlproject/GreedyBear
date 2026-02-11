#!/bin/bash

date
echo "starting wait_for_it for uwsgi"
/opt/deploy/greedybear/docker/wait-for-it.sh -t 15 postgres:$DB_PORT
date

until cd /opt/deploy/greedybear
do
    echo "Waiting for server volume..."
done

# Apply database migrations
echo "Waiting for db to be ready..."
# Create cache table for Django Q monitoring (idempotent)
python manage.py shell -c "
from django.db import connection
from django.core.management import call_command
try:
    if 'greedybear_cache' not in connection.introspection.table_names():
        call_command('createcachetable', 'greedybear_cache')
except Exception as e:
    print(f'Warning: Failed to create cache table: {e}')
"
python manage.py makemigrations durin
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput

echo "------------------------------"
echo "DEBUG: " $DEBUG
echo "DJANGO_TEST_SERVER: " $DJANGO_TEST_SERVER
echo "------------------------------"

if [[ $DEBUG == "True" ]] && [[ $DJANGO_TEST_SERVER == "True" ]];
then
    python manage.py runserver 0.0.0.0:8001
else
    /usr/local/bin/uwsgi --ini /etc/uwsgi/sites/greedybear.ini  --stats 127.0.0.1:1717 --stats-http
fi
