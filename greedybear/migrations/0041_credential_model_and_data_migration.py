"""
Migration to replace the credentials ArrayField on CowrieSession with
a normalized Credential model using a ManyToMany relationship.
"""
from django.db import migrations, models


def migrate_credentials(apps, schema_editor):
    schema_editor.execute("""
        INSERT INTO greedybear_credential (username, password)
        SELECT DISTINCT
            split_part(cred, ' | ', 1),
            split_part(cred, ' | ', 2)
        FROM greedybear_cowriesession, unnest(old_credentials) AS cred
        WHERE cred LIKE '%% | %%'
        ON CONFLICT DO NOTHING;
    """)

    schema_editor.execute("""
        INSERT INTO greedybear_cowriesession_credentials (cowriesession_id, credential_id)
        SELECT DISTINCT s.session_id, c.id
        FROM greedybear_cowriesession s, unnest(s.old_credentials) AS cred
        JOIN greedybear_credential c
            ON c.username = split_part(cred, ' | ', 1)
            AND c.password = split_part(cred, ' | ', 2)
        WHERE cred LIKE '%% | %%'
        ON CONFLICT DO NOTHING;
    """)


class Migration(migrations.Migration):

    dependencies = [
        ("greedybear", "0040_alter_tag_key"),
    ]

    operations = [
        # Step 1: Rename old ArrayField to preserve existing data
        migrations.RenameField(
            model_name="cowriesession",
            old_name="credentials",
            new_name="old_credentials",
        ),
        # Step 2: Create new Credential model
        migrations.CreateModel(
            name="Credential",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("username", models.CharField(max_length=256)),
                ("password", models.CharField(max_length=256)),
            ],
            options={
                "indexes": [
                    models.Index(fields=["username"], name="greedybear__usernam_29c9d6_idx"),
                    models.Index(fields=["password"], name="greedybear__passwor_6a8f16_idx"),
                ],
                "constraints": [
                    models.UniqueConstraint(fields=["username", "password"], name="unique_credential"),
                ],
            },
        ),
        # Step 3: Add new ManyToMany credentials field
        migrations.AddField(
            model_name="cowriesession",
            name="credentials",
            field=models.ManyToManyField(blank=True, to="greedybear.credential"),
        ),
        # Step 4: Migrate data from old_credentials into Credential objects
        migrations.RunPython(migrate_credentials, reverse_code=migrations.RunPython.noop),
        # Step 5: Remove old ArrayField now that data is migrated
        migrations.RemoveField(
            model_name="cowriesession",
            name="old_credentials",
        ),
    ]