# Generated migration for ThreatFox and AbuseIPDB feed models

from datetime import datetime

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('greedybear', '0034_tag'),
    ]

    operations = [
        migrations.CreateModel(
            name='ThreatFoxEntry',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.CharField(max_length=256, unique=True)),
                ('malware_family', models.CharField(blank=True, default='', max_length=64)),
                ('added', models.DateTimeField(blank=False, default=datetime.now)),
                ('last_seen_online', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'verbose_name_plural': 'ThreatFox entries',
            },
        ),
        migrations.CreateModel(
            name='AbuseIPDBEntry',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.CharField(max_length=256, unique=True)),
                ('abuse_confidence_score', models.IntegerField(default=0)),
                ('added', models.DateTimeField(blank=False, default=datetime.now)),
                ('last_reported_at', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'verbose_name_plural': 'AbuseIPDB entries',
            },
        ),
        migrations.AddIndex(
            model_name='threatfoxentry',
            index=models.Index(fields=['ip_address'], name='greedybear__ip_addr_threat_idx'),
        ),
        migrations.AddIndex(
            model_name='abuseipdbentry',
            index=models.Index(fields=['ip_address'], name='greedybear__ip_addr_abuse_idx'),
        ),
    ]
