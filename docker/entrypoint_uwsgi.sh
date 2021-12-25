#!/bin/bash

date
echo "starting wait_for_it for uwsgi"
/wait-for-it.sh -t 15 postgres:$DB_PORT
date

until cd /opt/deploy/greedybear
do
    echo "Waiting for server volume..."
done

# Apply database migrations
echo "Waiting for db to be ready..."
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
    /usr/local/bin/uwsgi --ini /etc/uwsgi/sites/greedybear.ini
fi
