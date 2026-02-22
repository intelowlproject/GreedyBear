from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("greedybear", "0036_add_sensors_to_ioc"),
    ]

    operations = [
        migrations.AlterField(
            model_name="sensor",
            name="address",
            field=models.CharField(max_length=39, unique=True),
        ),
        migrations.AlterField(
            model_name="statistics",
            name="source",
            field=models.CharField(max_length=39),
        ),
    ]
