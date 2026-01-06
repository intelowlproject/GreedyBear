from django.db import migrations


def disable_unwanted_honeypots(apps, schema_editor):
    """
    Ensure unwanted honeypots exist and are disabled.
    """
    GeneralHoneypot = apps.get_model("greedybear", "GeneralHoneypot")

    unwanted = [
        "ddospot",
        "ssh-rsa",
        "nginx",
    ]

    for name in unwanted:
        GeneralHoneypot.objects.get_or_create(
            name=name,
            defaults={"active": False},
        )


class Migration(migrations.Migration):

    dependencies = [
        ("greedybear", "0025_merge_20251223_2100"),
    ]

    operations = [
        migrations.RunPython(
            disable_unwanted_honeypots,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
