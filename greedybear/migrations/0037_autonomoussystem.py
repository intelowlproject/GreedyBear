import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("greedybear", "0036_add_sensors_to_ioc"),
    ]

    operations = [
        migrations.CreateModel(
            name="AutonomousSystem",
            fields=[
                (
                    "asn",
                    models.IntegerField(
                        primary_key=True,
                        serialize=False,
                        unique=True,
                    ),
                ),
                (
                    "name",
                    models.CharField(
                        blank=True,
                        default="",
                        max_length=256,
                    ),
                ),
            ],
        ),
        migrations.RemoveField(
            model_name="ioc",
            name="asn",
        ),
        migrations.AddField(
            model_name="ioc",
            name="autonomous_system",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="iocs",
                to="greedybear.autonomoussystem",
            ),
        ),
    ]
