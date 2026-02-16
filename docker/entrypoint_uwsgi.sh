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
python manage.py createcachetable
python manage.py makemigrations durin
python manage.py migrate

# Collect static files, overwriting existing ones
python manage.py collectstatic --noinput --clear --verbosity 0

# Fix log file ownership (manage.py commands above run as root and may create new log files)
chown -R 2000:82 /var/log/greedybear

# Obtain the current GreedyBear version number
. /opt/deploy/greedybear/docker/.version
export REACT_APP_GREEDYBEAR_VERSION

echo "------------------------------"
echo "GreedyBear $REACT_APP_GREEDYBEAR_VERSION"
echo "DEBUG: " $DEBUG
echo "DJANGO_TEST_SERVER: " $DJANGO_TEST_SERVER
echo "------------------------------"

if [[ $DEBUG == "True" ]] && [[ $DJANGO_TEST_SERVER == "True" ]];
then
    python manage.py runserver 0.0.0.0:8001
else
    /usr/local/bin/uwsgi --ini /etc/uwsgi/sites/greedybear.ini  --stats 127.0.0.1:1717 --stats-http
fi
