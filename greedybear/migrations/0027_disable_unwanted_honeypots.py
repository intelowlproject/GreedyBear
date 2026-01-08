from django.db import migrations


def disable_unwanted_honeypots(apps, schema_editor):
    """
    Ensure unwanted honeypots exist and are disabled.
    """
    GeneralHoneypot = apps.get_model("greedybear", "GeneralHoneypot")

    unwanted = [
        "Ddospot",
        "ssh-rsa",
        "NGINX",
    ]

    for name in unwanted:
        GeneralHoneypot.objects.get_or_create(
            name=name,
            defaults={"active": False},
        )


class Migration(migrations.Migration):

    dependencies = [
        ("greedybear", "0026_fix_charfield_null_true"),
    ]

    operations = [
        migrations.RunPython(
            disable_unwanted_honeypots,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
