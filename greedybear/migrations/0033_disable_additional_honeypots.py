from django.db import migrations


def disable_additional_honeypots(apps, schema_editor):
    """
    Disable additional honeypots: Fatt, P0f, ssh-dss, ssh-ed25519
    """
    GeneralHoneypot = apps.get_model("greedybear", "GeneralHoneypot")

    unwanted = [
        "Fatt",
        "P0f",
        "ssh-dss",
        "ssh-ed25519",
    ]

    for name in unwanted:
        GeneralHoneypot.objects.get_or_create(
            name=name,
            defaults={"active": False},
        )


class Migration(migrations.Migration):

    dependencies = [
        ("greedybear", "0032_torexitnode"),
    ]

    operations = [
        migrations.RunPython(
            disable_additional_honeypots,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
