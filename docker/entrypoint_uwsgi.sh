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
# Create cache table for Django Q monitoring (ignore error if exists)
python manage.py createcachetable || true
python manage.py makemigrations durin
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput

# Setup Django Q2 schedules
python manage.py setup_schedules

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
