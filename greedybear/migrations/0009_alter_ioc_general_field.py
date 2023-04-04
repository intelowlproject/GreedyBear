from django.db import migrations, models


def migrateData(apps, schema_editor):
    IOC = apps.get_model("greedybear", "IOC")

    for ioc in IOC.objects.all():
        for honeypot in ioc.general:
            if honeypot != "":
                if honeypot not in ioc.general_honeypot.all():
                    ioc.general_honeypot.create(name=honeypot)
        ioc.save()


class Migration(migrations.Migration):

    dependencies = [
        ("greedybear", "0008_auto_20230120_1548"),
    ]

    operations = [
        migrations.AddField(
            model_name="ioc",
            name="general_honeypot",
            field=models.ManyToManyField(blank=True, to="greedybear.GeneralHoneypot"),
        ),
        migrations.RunPython(migrateData),
        migrations.RemoveField(
            model_name="ioc",
            name="general",
        ),
        migrations.AlterField(
            model_name="ioc",
            name="type",
            field=models.CharField(choices=[("ip", "Ip"), ("domain", "Domain")], max_length=32),
        ),
    ]
