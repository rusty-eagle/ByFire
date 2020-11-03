# Generated by Django 3.1.1 on 2020-09-22 05:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('controlpanel', '0014_auto_20200922_0445'),
    ]

    operations = [
        migrations.AddField(
            model_name='iface',
            name='ipv4',
            field=models.CharField(blank=True, max_length=15, null=True),
        ),
        migrations.AddField(
            model_name='iface',
            name='ipv4_bc',
            field=models.CharField(blank=True, max_length=15, null=True),
        ),
        migrations.AddField(
            model_name='iface',
            name='ipv4_gw',
            field=models.CharField(blank=True, max_length=15, null=True),
        ),
        migrations.AddField(
            model_name='iface',
            name='ipv4_mask',
            field=models.CharField(blank=True, max_length=15, null=True),
        ),
        migrations.AddField(
            model_name='iface',
            name='ipv6',
            field=models.CharField(blank=True, max_length=23, null=True),
        ),
        migrations.AddField(
            model_name='iface',
            name='ipv6_bc',
            field=models.CharField(blank=True, max_length=23, null=True),
        ),
        migrations.AddField(
            model_name='iface',
            name='ipv6_gw',
            field=models.CharField(blank=True, max_length=23, null=True),
        ),
        migrations.AddField(
            model_name='iface',
            name='ipv6_mask',
            field=models.CharField(blank=True, max_length=23, null=True),
        ),
        migrations.AddField(
            model_name='iface',
            name='mtu',
            field=models.IntegerField(default=1500),
        ),
        migrations.AddField(
            model_name='iface',
            name='status',
            field=models.CharField(choices=[('up', 'Up'), ('down', 'Down')], default='up', max_length=10),
        ),
        migrations.AlterField(
            model_name='iface',
            name='dhcp6',
            field=models.BooleanField(default=False),
        ),
    ]
