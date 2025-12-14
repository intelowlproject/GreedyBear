from django.contrib.postgres.indexes import GinIndex
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("greedybear", "0022_whatsmyip"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="cowriesession",
            index=GinIndex(
                fields=["credentials"],
                name="greedybear_credentials_gin_idx",
            ),
        ),
    ]

