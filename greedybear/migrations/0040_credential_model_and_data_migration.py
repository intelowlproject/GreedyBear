"""
Migration to replace the credentials ArrayField on CowrieSession with
a normalized Credential model using a ManyToMany relationship.


"""
from django.db import migrations, models
from django.db.models import Q
import functools
import operator

def migrate_credentials(apps, schema_editor):
    CowrieSession = apps.get_model("greedybear", "CowrieSession")
    Credential = apps.get_model("greedybear", "Credential")

    for session in CowrieSession.objects.iterator():
        pairs = []
        for credential_str in session.old_credentials or []:
            try:
                username, password = credential_str.split(" | ", 1)
                pairs.append((username, password))
            except ValueError:
                continue

        if not pairs:
            continue

        Credential.objects.bulk_create(
            [Credential(username=u, password=p) for u, p in pairs],
            ignore_conflicts=True,
        )

        q = functools.reduce(operator.or_, [Q(username=u, password=p) for u, p in pairs])
        credentials = Credential.objects.filter(q)
        session.credentials.add(*credentials)


class Migration(migrations.Migration):

    dependencies = [
        ("greedybear", "0039_ioc_attacker_country_sensor_country_and_more"),
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
