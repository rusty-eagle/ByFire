# Generated by Django 3.1.1 on 2020-09-26 05:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('controlpanel', '0023_system_unattended_upgrades'),
    ]

    operations = [
        migrations.CreateModel(
            name='BlockList',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('filename', models.CharField(max_length=512)),
                ('url', models.CharField(max_length=512)),
            ],
        ),
    ]
