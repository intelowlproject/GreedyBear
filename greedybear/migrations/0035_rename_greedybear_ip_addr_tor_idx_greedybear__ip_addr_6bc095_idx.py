from django.db import migrations

def safe_rename_index(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM pg_indexes
                WHERE indexname = 'greedybear_ip_addr_tor_idx'
            ) THEN
                ALTER INDEX greedybear_ip_addr_tor_idx
                RENAME TO greedybear_ip_addr_6bc095_idx;
            END IF;
        END$$;
        """)


class Migration(migrations.Migration):

    dependencies = [
        ('greedybear', '0034_remove_unused_log4pot'),
    ]

    operations = [
        migrations.RunPython(safe_rename_index),
    ]