#!/bin/bash

# Apply database migrations
# Create cache table for Django Q monitoring (idempotent)
python manage.py createcachetable

# Make durin migrations and migrate
python manage.py makemigrations durin
python manage.py migrate

# Collect static files, overwriting existing ones
python manage.py collectstatic --noinput --clear --verbosity 0

# Fix log file ownership (manage.py commands above run as root and may create new log files)
chown -R 2000:82 /var/log/greedybear

# Obtain the current GreedyBear version number
. /opt/deploy/greedybear/docker/.version
export VITE_GREEDYBEAR_VERSION

echo "------------------------------"
echo "GreedyBear $VITE_GREEDYBEAR_VERSION"
echo "DEBUG: $DEBUG"
echo "DJANGO_TEST_SERVER: $DJANGO_TEST_SERVER"
echo "------------------------------"

exec "$@"
