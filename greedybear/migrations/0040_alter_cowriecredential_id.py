from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("greedybear", "0039_migrate_credentials_data"),
    ]

    operations = [
        migrations.AlterField(
            model_name="cowriecredential",
            name="id",
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID"),
        ),
    ]
