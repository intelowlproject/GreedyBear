"""
Generated data migration to move `cowrie` and `log4j` boolean flags
into the `GeneralHoneypot` many-to-many relationship.

This migration ensures that `Cowrie` and `Log4pot` entries exist in
`GeneralHoneypot` and for each IOC that had the boolean flags set it
adds the corresponding honeypot to the `general_honeypot` M2M.
"""
from django.db import migrations


def migrate_cowrie_log4j_to_general(apps, schema_editor):
    GeneralHoneypot = apps.get_model("greedybear", "GeneralHoneypot")
    IOC = apps.get_model("greedybear", "IOC")

    # Ensure honeypot entries exist
    cowrie_hp, _ = GeneralHoneypot.objects.get_or_create(name="Cowrie", defaults={"active": True})
    log4pot_hp, _ = GeneralHoneypot.objects.get_or_create(name="Log4pot", defaults={"active": True})

    # Migrate existing IOC rows
    for ioc in IOC.objects.all():
        try:
            # Some historical DBs might not yet have these fields; use getattr with default
            if getattr(ioc, "cowrie", False):
                ioc.general_honeypot.add(cowrie_hp)
            if getattr(ioc, "log4j", False):
                ioc.general_honeypot.add(log4pot_hp)
        except Exception:
            # Be resilient to odd DB states; continue migrating other rows
            continue


class Migration(migrations.Migration):

    dependencies = [
        ("greedybear", "0029_remove_hardcoded_honeypots"),
    ]

    operations = [
        migrations.RunPython(migrate_cowrie_log4j_to_general, reverse_code=migrations.RunPython.noop),
    ]
