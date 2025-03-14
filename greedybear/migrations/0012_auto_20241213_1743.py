# Generated by Django 4.2.15 on 2024-12-13 17:43

from django.db import migrations


def migrate_data(apps, schema_editor):
    IOC = apps.get_model("greedybear", "IOC")
    for ioc in IOC.objects.all():
        if not ioc.days_seen:
            ioc.days_seen = []
        if not ioc.interaction_count:
            ioc.interaction_count = ioc.attack_count
        if not ioc.ip_reputation:
            ioc.ip_reputation = ""
        if not ioc.destination_ports:
            ioc.destination_ports = []
        if not ioc.login_attempts:
            ioc.login_attempts = 0
        ioc.save()


class Migration(migrations.Migration):
    dependencies = [
        ("greedybear", "0011_rename_times_seen_ioc_attack_count_ioc_asn_and_more"),
    ]

    operations = [
        migrations.RunPython(migrate_data),
    ]
