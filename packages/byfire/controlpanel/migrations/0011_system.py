# Generated by Django 3.1.1 on 2020-09-20 05:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('controlpanel', '0010_iptablepolicy'),
    ]

    operations = [
        migrations.CreateModel(
            name='System',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('hostname', models.CharField(default='firewall', max_length=128)),
                ('domain', models.CharField(default='lan', max_length=128)),
                ('apply_iptables', models.BooleanField(default=False)),
            ],
        ),
    ]
