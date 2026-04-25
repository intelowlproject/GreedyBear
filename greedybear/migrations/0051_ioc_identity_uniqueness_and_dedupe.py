from django.db import migrations, models


def merge_duplicate_iocs(apps, schema_editor):
    IOC = apps.get_model("greedybear", "IOC")
    Tag = apps.get_model("greedybear", "Tag")
    CowrieSession = apps.get_model("greedybear", "CowrieSession")

    duplicates = IOC.objects.values("name", "type").annotate(cnt=models.Count("id")).filter(cnt__gt=1)

    for dup in duplicates.iterator():
        same_identity = list(IOC.objects.filter(name=dup["name"], type=dup["type"]).order_by("id"))
        canonical = same_identity[0]
        to_merge = same_identity[1:]

        first_seen_values = [ioc.first_seen for ioc in same_identity if ioc.first_seen is not None]
        if first_seen_values:
            canonical.first_seen = min(first_seen_values)

        last_seen_values = [ioc.last_seen for ioc in same_identity if ioc.last_seen is not None]
        if last_seen_values:
            canonical.last_seen = max(last_seen_values)

        canonical.days_seen = sorted({day for ioc in same_identity for day in (ioc.days_seen or []) if day is not None})
        canonical.number_of_days_seen = len(canonical.days_seen)
        canonical.attack_count = sum((ioc.attack_count or 0) for ioc in same_identity)
        canonical.interaction_count = sum((ioc.interaction_count or 0) for ioc in same_identity)
        canonical.login_attempts = sum((ioc.login_attempts or 0) for ioc in same_identity)
        canonical.scanner = any(ioc.scanner for ioc in same_identity)
        canonical.payload_request = any(ioc.payload_request for ioc in same_identity)

        canonical.related_urls = sorted({item for ioc in same_identity for item in (ioc.related_urls or []) if item})
        canonical.destination_ports = sorted({item for ioc in same_identity for item in (ioc.destination_ports or []) if item is not None})
        canonical.firehol_categories = sorted({item for ioc in same_identity for item in (ioc.firehol_categories or []) if item})

        if not canonical.ip_reputation:
            for ioc in same_identity:
                if ioc.ip_reputation:
                    canonical.ip_reputation = ioc.ip_reputation
                    break

        if not canonical.attacker_country:
            for ioc in same_identity:
                if ioc.attacker_country:
                    canonical.attacker_country = ioc.attacker_country
                    break

        if not canonical.attacker_country_code:
            for ioc in same_identity:
                if ioc.attacker_country_code:
                    canonical.attacker_country_code = ioc.attacker_country_code
                    break

        if canonical.autonomous_system_id is None:
            for ioc in same_identity:
                if ioc.autonomous_system_id is not None:
                    canonical.autonomous_system_id = ioc.autonomous_system_id
                    break

        canonical.save()

        for duplicate in to_merge:
            canonical.honeypots.add(*duplicate.honeypots.all())
            canonical.sensors.add(*duplicate.sensors.all())
            canonical.credentials.add(*duplicate.credentials.all())

            related_to_duplicate = duplicate.related_ioc.exclude(pk=canonical.pk)
            if related_to_duplicate.exists():
                canonical.related_ioc.add(*related_to_duplicate)

            Tag.objects.filter(ioc_id=duplicate.pk).update(ioc_id=canonical.pk)
            CowrieSession.objects.filter(source_id=duplicate.pk).update(source_id=canonical.pk)

            duplicate.delete()


class Migration(migrations.Migration):
    dependencies = [
        ("greedybear", "0050_attackeractivitybucket"),
    ]

    operations = [
        migrations.RunPython(merge_duplicate_iocs, migrations.RunPython.noop),
    ]
