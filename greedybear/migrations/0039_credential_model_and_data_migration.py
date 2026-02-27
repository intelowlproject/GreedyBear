"""
Migration to replace the credentials ArrayField on CowrieSession with
a normalized Credential model using a ManyToMany relationship.

Steps:
1. Rename old credentials ArrayField to old_credentials (preserve data)
2. Create new Credential model
3. Add new credentials ManyToManyField
4. Migrate data from old_credentials into Credential objects
5. Remove old_credentials field
"""
from django.db import migrations, models


def migrate_credentials(apps, schema_editor):
    CowrieSession = apps.get_model("greedybear", "CowrieSession")
    Credential = apps.get_model("greedybear", "Credential")

    for session in CowrieSession.objects.all():
        for credential_str in session.old_credentials or []:
            try:
                username, password = credential_str.split(" | ", 1)
                credential, _ = Credential.objects.get_or_create(
                    username=username,
                    password=password,
                )
                session.credentials.add(credential)
            except ValueError:
                continue


class Migration(migrations.Migration):

    dependencies = [
        ("greedybear", "0038_add_tag_model"),
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
                "unique_together": {("username", "password")},
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
