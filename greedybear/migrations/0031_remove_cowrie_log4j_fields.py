"""
Schema migration to remove the legacy `cowrie` and `log4j` boolean
fields from the `IOC` model now that they are represented by the
`general_honeypot` many-to-many relation.
"""
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("greedybear", "0030_migrate_cowrie_log4j"),
    ]

    operations = [
        migrations.RemoveField(model_name="ioc", name="cowrie"),
        migrations.RemoveField(model_name="ioc", name="log4j"),
    ]
