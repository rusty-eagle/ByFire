# Generated by Django 3.1.1 on 2020-09-24 06:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('controlpanel', '0020_dhcpsubnet_zone_name'),
    ]

    operations = [
        migrations.AddField(
            model_name='system',
            name='time_server',
            field=models.CharField(default='ntp.ubuntu.com', max_length=128),
        ),
        migrations.AddField(
            model_name='system',
            name='timesync',
            field=models.BooleanField(default=True),
        ),
    ]
