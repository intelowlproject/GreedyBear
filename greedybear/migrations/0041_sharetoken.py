# Generated migration: squashes 0041_revokedtoken + 0042_sharetoken_delete_revokedtoken
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("greedybear", "0040_alter_tag_key"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="ShareToken",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="share_tokens",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "token_hash",
                    models.CharField(
                        db_index=True,
                        help_text="SHA-256 hex digest of the raw signed token.",
                        max_length=64,
                        unique=True,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("revoked", models.BooleanField(default=False)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("reason", models.CharField(blank=True, default="", max_length=256)),
            ],
        ),
    ]
