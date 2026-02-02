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

    credentials_to_create = []
    chunk_size = 1000

    for session in CowrieSession.objects.all().iterator(chunk_size=chunk_size):
        for cred_str in session.credentials:
            # Parse "username | password" format
            if " | " in cred_str:
                username, password = cred_str.split(" | ", 1)
            else:
                # Fallback for malformed data
                username, password = "", cred_str

            credentials_to_create.append(
                CowrieCredential(
                    session=session,
                    username=username[:256],  # Truncate to max_length
                    password=password[:256],
                )
            )

            if len(credentials_to_create) >= chunk_size:
                CowrieCredential.objects.bulk_create(credentials_to_create, ignore_conflicts=True)
                credentials_to_create = []

    if credentials_to_create:
        CowrieCredential.objects.bulk_create(credentials_to_create, ignore_conflicts=True)


def reverse_migrate(apps, schema_editor):
    CowrieCredential = apps.get_model("greedybear", "CowrieCredential")
    CowrieCredential.objects.all().delete()


class Migration(migrations.Migration):

    dependencies = [
        ("greedybear", "0035_add_unique_constraint_to_credentials"),
    ]

    operations = [
        migrations.RunPython(migrate_credentials_to_table, reverse_code=reverse_migrate),
        # remove the credentials ArrayField after migrating data
        migrations.RemoveField(
            model_name="cowriesession",
            name="credentials",
        ),
    ]

