from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("greedybear", "0051_ioc_identity_uniqueness_and_dedupe"),
    ]

    operations = [
        migrations.AddConstraint(
            model_name="ioc",
            constraint=models.UniqueConstraint(fields=("name", "type"), name="unique_ioc_identity"),
        ),
    ]
