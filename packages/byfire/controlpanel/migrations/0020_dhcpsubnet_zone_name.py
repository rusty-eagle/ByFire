# Generated by Django 3.1.1 on 2020-09-24 04:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('controlpanel', '0019_auto_20200924_0440'),
    ]

    operations = [
        migrations.AddField(
            model_name='dhcpsubnet',
            name='zone_name',
            field=models.CharField(default='internal', max_length=15),
        ),
    ]