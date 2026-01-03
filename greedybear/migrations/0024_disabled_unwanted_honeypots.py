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
        try:
            hp = GeneralHoneypot.objects.get(name__iexact=name)
            if hp.active:
                hp.active = False
                hp.save(update_fields=["active"])
        except GeneralHoneypot.DoesNotExist:
            GeneralHoneypot.objects.create(
                name=name,
                active=False,
            )


class Migration(migrations.Migration):

    dependencies = [
        ("greedybear", "0023_rename_massscanners_massscanner_and_more"),
    ]

    operations = [
        migrations.RunPython(
            disable_unwanted_honeypots,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
