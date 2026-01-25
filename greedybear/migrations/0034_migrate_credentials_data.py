"""
Data migration to populate CowrieCredential table from existing
CowrieSession.credentials ArrayField data.

For each session with credentials in the legacy array format, creates
individual CowrieCredential records in the normalized table.
"""
from django.db import migrations


def migrate_credentials_to_table(apps, schema_editor):
    CowrieSession = apps.get_model("greedybear", "CowrieSession")
    CowrieCredential = apps.get_model("greedybear", "CowrieCredential")

    for session in CowrieSession.objects.all():
        for cred_str in session.credentials:
            # Parse "username | password" format
            if " | " in cred_str:
                username, password = cred_str.split(" | ", 1)
            else:
                # Fallback for malformed data
                username, password = "", cred_str
            
            # Use get_or_create to handle duplicates gracefully
            CowrieCredential.objects.get_or_create(
                session=session,
                username=username[:256],  # Truncate to max_length
                password=password[:256],
            )


def reverse_migrate(apps, schema_editor):
    CowrieCredential = apps.get_model("greedybear", "CowrieCredential")
    CowrieCredential.objects.all().delete()


class Migration(migrations.Migration):

    dependencies = [
        ("greedybear", "0033_add_unique_constraint_to_credentials"),
    ]

    operations = [
        migrations.RunPython(migrate_credentials_to_table, reverse_code=reverse_migrate),
    ]
