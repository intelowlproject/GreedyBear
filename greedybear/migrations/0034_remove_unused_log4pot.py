"""
Data migration to remove Log4pot from GeneralHoneypot if it has no associated IOCs.

This migration fixes issue #773 where Log4pot appears as an active honeypot
in the admin interface and dashboard, despite having no data.

The migration 0030_migrate_cowrie_log4j.py created Log4pot with active=True
unconditionally, even for instances that never had Log4pot running. This
migration cleans that up by removing the honeypot entry if it has no IOC data.

If a user enables Log4Pot on their T-Pot instance later, the extraction
pipeline will automatically create the GeneralHoneypot entry when it
encounters Log4pot data.
"""

from django.db import migrations


def remove_unused_log4pot(apps, schema_editor):
    GeneralHoneypot = apps.get_model("greedybear", "GeneralHoneypot")
    IOC = apps.get_model("greedybear", "IOC")

    try:
        hp = GeneralHoneypot.objects.get(name="Log4pot")
        if not IOC.objects.filter(general_honeypot=hp).exists():
            hp.delete()
    except GeneralHoneypot.DoesNotExist:
        pass


class Migration(migrations.Migration):

    dependencies = [
        ("greedybear", "0033_disable_additional_honeypots"),
    ]

    operations = [
        migrations.RunPython(remove_unused_log4pot, reverse_code=migrations.RunPython.noop),
    ]
