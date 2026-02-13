#!/bin/bash
# Healthcheck script for uwsgi container
# Verifies that required database tables exist before qcluster starts

set -e

# Check if Django can connect to the database and required tables exist
python3 << 'PYEOF'
import os
import sys
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'greedybear.settings')
django.setup()

from django.db import connection

required_tables = ['greedybear_cache', 'django_q_ormq']

try:
    with connection.cursor() as cursor:
        for table in required_tables:
            cursor.execute(
                "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = %s)",
                [table]
            )
            exists = cursor.fetchone()[0]
            if not exists:
                print(f"Table {table} does not exist yet", file=sys.stderr)
                sys.exit(1)
    print("All required tables exist")
    sys.exit(0)
except Exception as e:
    print(f"Healthcheck failed: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
